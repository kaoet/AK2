#define _GNU_SOURCE
#include "executor.h"
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sched.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>

#include "log.h"

#define UPDATE_IF_GREATER(a,b) a=(a)>(b)?(a):(b)
#define CGROUP_MEMORY "/sys/fs/cgroup/memory"
#define CHILD_STACK_SIZE (8 * 1024 * 1024)

static double REALTIME_RATE = 1;
static int REALTIME_OFFSET = 1000;
static double MEMORY_LIMIT_RATE = 1;
static long MEMORY_LIMIT_OFFSET = 4096;

struct context {
	const struct exec_arg *arg;
	struct exec_result *result;
	pid_t child_pid;
	uid_t child_uid;
	gid_t child_gid;
	int cgroup_id;
	long start_time;
};

static void set_rlimits(const struct exec_limit *limit)
{
	struct rlimit rlimit;

	//File Size
	//SIGXFSZ
	if (limit->output_limit >= 0) {
		rlimit.rlim_cur = rlimit.rlim_max = limit->output_limit;
		setrlimit(RLIMIT_FSIZE, &rlimit);
	}
	//No Core File
	rlimit.rlim_cur = rlimit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlimit);

	//Execute Time
	//To send SIGXCPU
	//Sys + User
	if (limit->time_limit >= 0) {
		rlimit.rlim_cur =
		    ceil(limit->time_limit * REALTIME_RATE +
			 REALTIME_OFFSET / 1000.0);
		//To SIGKILL the program when he ignored SIGXCPU
		rlimit.rlim_max = rlimit.rlim_cur + 1;
		setrlimit(RLIMIT_CPU, &rlimit);
	}
	//NICE
	//The real limit set is 20 - rlim_cur
	rlimit.rlim_cur = rlimit.rlim_max = 20;
	setrlimit(RLIMIT_NICE, &rlimit);

	//Number of processes
	if (limit->process_limit >= 0) {
		rlimit.rlim_cur = rlimit.rlim_max = limit->process_limit;
		setrlimit(RLIMIT_NPROC, &rlimit);
	}
}

static void close_fds()
{
	char *fd_dir_path;
	DIR *dir_fd;
	struct dirent *fd_file;

	assert(asprintf(&fd_dir_path, "/proc/%d/fd", getpid()) != -1);
	dir_fd = opendir(fd_dir_path);
	assert(dir_fd != NULL);
	free(fd_dir_path);

	while ((fd_file = readdir(dir_fd)) != NULL) {
		if (atoi(fd_file->d_name) > 2)
			close(atoi(fd_file->d_name));
	}
	closedir(dir_fd);
}

static int do_child(void *arg)
{
    DBG("child spawned");
    struct context *context = (struct context *)arg;
    
	//Close File Descriptor
	close_fds();

	//Set Root Directory
	if (context->arg->root != NULL)
	    assert(chroot(context->arg->root) == 0);

	//Set work directory
	if (context->arg->cwd != NULL)
	    assert(chdir(context->arg->cwd) == 0);

	//Redirect standard I/O
	if (context->arg->input_file != NULL)
	    assert(freopen(context->arg->input_file, "r", stdin) != NULL);
	if (context->arg->output_file != NULL)
	    assert(freopen(context->arg->output_file, "w", stdout) != NULL);
	if (context->arg->error_file != NULL)
	    assert(freopen(context->arg->error_file, "w", stderr) != NULL);

	//Set gid & uid
	assert(setgid(context->child_gid) == 0);
	assert(setuid(context->child_uid) == 0);

	DBG("child euid=%d uid=%d egid=%d gid=%d\n", geteuid(), getuid(),
	    getegid(), getgid());

	//Set limits
	set_rlimits(&context->arg->limit);

	// wait parent to ready
	raise(SIGSTOP);

    char *env[] = {"PATH=/bin:/usr/local/bin:/usr/bin", NULL};
	ERR("execvp=%d", execvpe(context->arg->command, context->arg->argv, env));
	ERR("errno=%d", errno);
	return errno;
}

static void create_cgroup(struct context *context)
{
    context->cgroup_id = rand();
    
    char *path;
    assert(asprintf(&path, CGROUP_MEMORY "/%d", context->cgroup_id) != -1);
    assert(mkdir(path, 0755) == 0);
    free(path);
    
    if (context->arg->limit.memory_limit > 0) {
        assert(asprintf(&path, CGROUP_MEMORY "/%d/memory.soft_limit_in_bytes", context->cgroup_id) != -1);
        FILE *f = fopen(path, "w");
        assert(f != NULL);
        assert(fprintf(f, "%ld", context->arg->limit.memory_limit) > 0);
        assert(fclose(f) == 0);
        free(path);
        
        long hard_memory_limit = ceil(context->arg->limit.memory_limit * MEMORY_LIMIT_RATE + MEMORY_LIMIT_OFFSET);
        DBG("hard limit=%ld\n", hard_memory_limit);
        
        assert(asprintf(&path, CGROUP_MEMORY "/%d/memory.limit_in_bytes", context->cgroup_id) != -1);
        f = fopen(path, "w");
        assert(f != NULL);
        assert(fprintf(f, "%ld", hard_memory_limit) > 0);
        assert(fclose(f) == 0);
        free(path);
        
        assert(asprintf(&path, CGROUP_MEMORY "/%d/memory.memsw.limit_in_bytes", context->cgroup_id) != -1);
        f = fopen(path, "w");
        assert(f != NULL);
        assert(fprintf(f, "%ld", hard_memory_limit) > 0);
        assert(fclose(f) == 0);
        free(path);
    }
}

static void add_to_cgroup(struct context *context)
{
    char *path;
    assert(asprintf(&path, CGROUP_MEMORY "/%d/tasks", context->cgroup_id) != -1);
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    assert(fprintf(f, "%d", context->child_pid) > 0);
    assert(fclose(f) == 0);
    free(path);
}

static long get_memory_usage(struct context *context)
{
    char *usage_path;
    assert(asprintf(&usage_path, CGROUP_MEMORY "/%d/memory.memsw.max_usage_in_bytes", context->cgroup_id) != -1);
    FILE *f = fopen(usage_path, "r");
    free(usage_path);
    assert(f != NULL);
    
    long usage;
    assert(fscanf(f, "%ld", &usage) == 1);
    fclose(f);
    return usage;
}

static void kill_all(struct context *context)
{
    char *cgroup_path;
    assert(asprintf(&cgroup_path, CGROUP_MEMORY "/%d", context->cgroup_id) != -1);
    
    for (;;) {
        //DBG("Kill round");
        char *tasks_path;
	    assert(asprintf(&tasks_path, CGROUP_MEMORY "/%d/tasks", context->cgroup_id) != -1);
	    FILE * f = fopen(tasks_path, "r");
	    free(tasks_path);
	    assert(f != NULL);
        
        int pid;
        while (fscanf(f, "%d", &pid) == 1) {
            //DBG("Killing %d", pid);
            kill(pid, SIGKILL);
        }
        fclose(f);
        
        // Wait a moment
        sched_yield();
        
        if (rmdir(cgroup_path) == 0)
            break;
        if (errno != EBUSY) {
            ERR("rmdir cgroup memory, errno=%d", errno);
            break;
        }
    }
    
    free(cgroup_path);
}

static void realtime_alarm_handler(int signo, siginfo_t * info, void *data)
{
	struct context *context = (struct context *)info->si_value.sival_ptr;
	context->result->type = EXEC_TLE;
	kill(context->child_pid, SIGKILL);
}

static inline long time_of_day()
{
	struct timeval tp;
	gettimeofday(&tp, NULL);
	return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

static enum exec_result_type loop_body(struct context *context)
{
	const struct exec_arg *arg = context->arg;
	const struct exec_limit *limit = &arg->limit;
	struct exec_result *result = context->result;
	struct rusage rusage;
	int status;
	pid_t pid;

 WaitAgain:
	pid = wait4(context->child_pid, &status, WUNTRACED, &rusage);
	
	result->real_time = time_of_day() - context->start_time;

	if (limit->time_limit >= 0 && result->type == EXEC_UNKNOWN) {
		if (result->user_time > limit->time_limit
		    || result->real_time >
		    limit->time_limit * REALTIME_RATE + REALTIME_OFFSET) {
			return EXEC_TLE;
		}
	}

	if (pid == -1) {
		if (errno == EINTR) {
			DBG("wait4 returned EINTR. I've to wait again");
			goto WaitAgain;
		} else {
			ERR("wait4 returned -1 & errno = %d\n", errno);
			return EXEC_VIOLATION;
		}
	}

	UPDATE_IF_GREATER(result->user_time,
			  rusage.ru_utime.tv_sec * 1000 +
			  rusage.ru_utime.tv_usec / 1000);

    context->result->memory = get_memory_usage(context);
    if (limit->memory_limit > 0 && result->memory >= limit->memory_limit) {
	    return EXEC_MLE;
	}

	if (limit->time_limit >= 0 && result->type == EXEC_UNKNOWN) {
		if (result->user_time > limit->time_limit
		    || result->real_time >
		    limit->time_limit * REALTIME_RATE + REALTIME_OFFSET) {
			return EXEC_TLE;
		}
	}

	if (WIFEXITED(status)) {
		int exit_status = WEXITSTATUS(status);
		result->exit_status = exit_status;
		if (exit_status == 0) {
			return EXEC_SUCCESS;
		} else {
			return EXEC_FAILURE;
		}
	} else if (WIFSIGNALED(status)) {
		int signo = WTERMSIG(status);
		if (result->type == EXEC_UNKNOWN) {
			switch (signo) {
			case SIGXFSZ:
				return EXEC_OLE;
			case SIGXCPU:
				return EXEC_TLE;
			case SIGSEGV:
				return EXEC_MEM_VIOLATION;
			case SIGFPE:
				return EXEC_MATH_ERROR;
			}
		}
		result->exit_status = signo;
		return EXEC_CRASHED;
	} else if (WIFSTOPPED(status)) {
	    DBG("child stopped");
		kill(context->child_pid, SIGCONT);
		return EXEC_UNKNOWN;
	} else {
		ERR("Not exit/signaled/stopped");
		return EXEC_VIOLATION;
	}
}

static void do_parent(struct context *context)
{
	timer_t realtime_timer = NULL;

	//Real Time Alarm to prevent infinite sleep
	if (context->arg->limit.time_limit >= 0) {
		struct sigevent event;
		struct itimerspec its;
		long time_limit =
		    context->arg->limit.time_limit * REALTIME_RATE +
		    REALTIME_OFFSET;

		event.sigev_notify = SIGEV_SIGNAL;
		event.sigev_signo = SIGRTMIN;
		event.sigev_value.sival_ptr = context;
		assert(timer_create(CLOCK_REALTIME, &event, &realtime_timer) !=
		       -1);

		memset(&its, 0, sizeof(struct itimerspec));
		its.it_value.tv_sec = time_limit / 1000;
		its.it_value.tv_nsec = time_limit % 1000 * 1000 * 1000;
		assert(timer_settime(realtime_timer, 0, &its, NULL) != -1);
	}
	
	add_to_cgroup(context);

	context->start_time = time_of_day();
	for (;;) {
		enum exec_result_type result = loop_body(context);
		if (result != EXEC_UNKNOWN) {
		    if (context->result->type == EXEC_UNKNOWN)
			    context->result->type = result;
			break;
		}
	}

	kill_all(context);

	if (realtime_timer)
		assert(timer_delete(realtime_timer) != -1);
}

void exec_execute(const struct exec_arg *_arg, struct exec_result *_result)
{
	struct context *context = malloc(sizeof(struct context));

	assert(context != NULL);
	context->arg = _arg;
	context->result = _result;
	context->child_uid = 10000 + rand() % 20000;
	context->child_gid = context->child_uid;
	DBG("uid=gid=%d", context->child_uid);

	memset(context->result, 0, sizeof(struct exec_result));
	context->result->type = EXEC_UNKNOWN;
	
	create_cgroup(context);

	context->child_pid = clone(do_child,  malloc(CHILD_STACK_SIZE) + CHILD_STACK_SIZE, SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET, context);
	DBG("child pid = %d\n", context->child_pid);
	assert(context->child_pid != -1);
	do_parent(context);

	free(context);
}

void exec_init()
{
	struct sigaction act;
	unsigned seed;
	FILE *urandom;
	struct timeval tval;
	int i;

	if (geteuid() != 0) {
		ERR("Please sudo me");
		exit(1);
	}

	sigemptyset(&act.sa_mask);
	act.sa_sigaction = realtime_alarm_handler;
	act.sa_flags = SA_SIGINFO;
	assert(sigaction(SIGRTMIN, &act, NULL) != -1);

	urandom = fopen("/dev/urandom", "r");
	assert(urandom != NULL);
	assert(fread(&seed, sizeof(seed), 1, urandom) == 1);
	fclose(urandom);
	
	gettimeofday(&tval, NULL);
	for (i = 0; i < sizeof(struct timeval) / sizeof(int); i++) {
		seed ^= *((int *)&tval + i);
	}
	srand(seed);
}

void exec_init_param(const char *key, const char *value)
{
	if (!strcmp(key, "exec.realtime_rate"))
		REALTIME_RATE = atof(value);
	else if (!strcmp(key, "exec.realtime_offset"))
		REALTIME_OFFSET = atoi(value);
	else if (!strcmp(key, "exec.memory_limit_rate"))
		MEMORY_LIMIT_RATE = atof(value);
	else if (!strcmp(key, "exec.memory_limit_offset"))
	    MEMORY_LIMIT_OFFSET = atol(value);
}
