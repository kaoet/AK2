#define _GNU_SOURCE
#include "executor.h"
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <sys/reg.h>
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
#include "hash.h"

#define UPDATE_IF_GREATER(a,b) a=(a)>(b)?(a):(b)

static double REALTIME_RATE = 1;
static int REALTIME_OFFSET = 1000;
static double MEMORY_LIMIT_RATE = 1.5;
static long STACK_LIMIT = 256 * 1024 * 1024;

struct process_info {
	long memory_usage;
	long fake_return_value;
	bool in_syscall, fake_return;
};

struct context {
	const struct exec_arg *arg;
	struct exec_result *result;
	pid_t child_pid;
	uid_t child_uid;
	gid_t child_gid;
	long start_time;
	struct hash *procs;
};

static void set_iptables(struct context *context)
{
	char *cmd_check, *cmd_add;
	sem_t *mutex;

	assert(asprintf(&cmd_check,
			"iptables -C OUTPUT -m owner --uid-owner %d -j DROP 2> /dev/null",
			context->child_uid) != -1);
	assert(asprintf(&cmd_add,
			"iptables -A OUTPUT -m owner --uid-owner %d -j DROP 2> /dev/null",
			context->child_uid) != -1);

	mutex = sem_open("ak2.iptables.lock", O_CREAT, 0644, 1);
	assert(mutex != SEM_FAILED);
	sem_wait(mutex);

	//Set iptables
	if (system(cmd_check) != 0)
		assert(system(cmd_add) == 0);

	sem_post(mutex);
	sem_close(mutex);

	free(cmd_check);
	free(cmd_add);
}

static void unset_iptables(struct context *context)
{
	char *cmd_del;
	sem_t *mutex;

	assert(asprintf(&cmd_del,
			"iptables -D OUTPUT -m owner --uid-owner %d -j DROP 2> /dev/null",
			context->child_uid) != -1);

	mutex = sem_open("ak2.iptables.lock", O_CREAT, 0644, 1);
	assert(mutex != SEM_FAILED);
	sem_wait(mutex);

	//Set iptables
	system(cmd_del);

	sem_post(mutex);
	sem_close(mutex);

	free(cmd_del);
}

static void set_rlimits(const struct exec_limit *limit)
{

	struct rlimit rlimit;

	//File Size
	//SIGXFSZ
	if (limit->output_limit >= 0) {
		rlimit.rlim_cur = rlimit.rlim_max = limit->output_limit;
		setrlimit(RLIMIT_FSIZE, &rlimit);
	}
	//Total Memory
	//Doubled
	if (limit->memory_limit >= 0) {
		rlimit.rlim_cur = rlimit.rlim_max = limit->memory_limit
		    * MEMORY_LIMIT_RATE;
		setrlimit(RLIMIT_AS, &rlimit);
	}
	//No Core File
	rlimit.rlim_cur = rlimit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlimit);

	//Stack
	rlimit.rlim_cur = rlimit.rlim_max = STACK_LIMIT;
	setrlimit(RLIMIT_STACK, &rlimit);

	//Execute Time
	//To send SIGXCPU
	//Sys + User
	if (limit->time_limit >= 0) {
		rlimit.rlim_cur = ceil(limit->time_limit / 1000.0);
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

static void do_child(struct context *context)
{
	//Close File Descriptor
	close_fds();

	//Set Root Directory
	assert(chroot(context->arg->root) == 0);

	//Set work directory
	assert(chdir(context->arg->cwd) == 0);

	//Redirect standard I/O
	assert(freopen(context->arg->input_file, "r", stdin) != NULL);
	assert(freopen(context->arg->output_file, "w", stdout) != NULL);
	assert(freopen(context->arg->error_file, "w", stderr) != NULL);

	//Set pgrp
	assert(setpgid(0, 0) == 0);

	//Set gid & uid
	assert(setgid(context->child_gid) == 0);
	assert(setuid(context->child_uid) == 0);

	DBG("child euid=%d uid=%d egid=%d gid=%d\n", geteuid(), getuid(),
	    getegid(), getgid());

	//Set limits
	set_rlimits(&context->arg->limit);

	//Trace me
	ptrace(PTRACE_TRACEME, 0, 0, 0);

	//Tell parent to prepare ptrace
	raise(SIGSTOP);

	ERR("execvp=%d", execvp(context->arg->command, context->arg->argv));
	ERR("errno=%d", errno);
	exit(errno);
}

static void kill_all(struct context *context)
{
	int status;
	do {
		pid_t pid = fork();

		assert(pid != -1);
		if (pid == 0) {
			setuid(context->child_uid);
			kill(-1, SIGKILL);
			exit(0);
		}
		// wait for it
		assert(waitpid(pid, &status, 0) == pid);
	} while (!WIFEXITED(status));

	// wait all process in the pgrp
	for (;;) {
		pid_t pid = waitpid(-context->child_pid, NULL, 0);
		// no more process
		if (pid == -1 && errno == ECHILD) {
			return;
		} else {
			assert(pid > 0);
		}
	}
}

static void realtime_alarm_handler(int signo, siginfo_t * info, void *data)
{
	struct context *context = (struct context *)info->si_value.sival_ptr;
	kill(context->child_pid, SIGXCPU);
}

static inline long time_of_day()
{
	struct timeval tp;
	gettimeofday(&tp, NULL);
	return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

static long get_memory_usage(pid_t pid)
{
	char *statm_path;
	FILE *file;
	long memory;

	assert(asprintf(&statm_path, "/proc/%d/statm", pid) != -1);
	file = fopen(statm_path, "r");
	assert(file != NULL);
	assert(fscanf(file, "%*d %*d %*d %*d %*d %ld", &memory) == 1);
	fclose(file);
	free(statm_path);
	return memory * getpagesize();
}

static enum exec_result_type check_syscall(struct context *context, pid_t pid)
{
	long syscall =
	    ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
	long mem_usage;
	struct process_info *pinfo;

	pinfo = (struct process_info *)hash_find(context->procs, pid);

	if (!pinfo->in_syscall) {
		pinfo->in_syscall = true;
		DBG("syscall = %ld", syscall);

		switch (syscall) {
		case SYS_brk:
		case SYS_mmap:
		case SYS_munmap:
		case SYS_mremap:
			//TODO SYS_shmXXX?
			mem_usage = get_memory_usage(pid);
			if (pinfo->memory_usage < mem_usage) {
				DBG("pid=%d oldmem=%ld newmem=%ld", pid,
				    pinfo->memory_usage, mem_usage);
				context->result->memory -= pinfo->memory_usage;
				pinfo->memory_usage = mem_usage;
				context->result->memory += pinfo->memory_usage;
				if (context->arg->limit.memory_limit >= 0
				    && context->result->memory >
				    context->arg->limit.memory_limit)
					return EXEC_MLE;
			}
			break;
		case SYS_setpgid:
			DBG("Caught setpgid");
			assert(ptrace
			       (PTRACE_POKEUSER, pid, sizeof(long) * ORIG_RAX,
				(void *)SYS_getpid) != -1);
			pinfo->fake_return = true;
			pinfo->fake_return_value = 0;
			break;
		}
	} else {
		pinfo->in_syscall = false;
		if (pinfo->fake_return) {
			assert(ptrace
			       (PTRACE_POKEUSER, pid, sizeof(long) * RAX,
				(void *)pinfo->fake_return_value) != -1);
			pinfo->fake_return = false;
		}
	}

	return EXEC_UNKNOWN;
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
    //Wait for any process in my child's pgrp
    pid = wait4(-context->child_pid, &status, 0, &rusage);

    if (pid == -1) {
        if (errno == ECHILD){
            //Maybe the process group has not built up?
            pid = wait4(context->child_pid, &status, 0, &rusage);
            assert(pid > 0);
        }else if(errno == EINTR){
            ERR("wait4 returned EINTR, I've to wait again");
            goto WaitAgain;
        }else{
            ERR("wait4 returned -1 & errno = %d\n",errno);
            return EXEC_VIOLATION;
        }
    }

	DBG("wait4 pid=%d", pid);

	UPDATE_IF_GREATER(result->user_time,
			  rusage.ru_utime.tv_sec * 1000 +
			  rusage.ru_utime.tv_usec / 1000);
	result->real_time = time_of_day() - context->start_time;

	if (limit->time_limit >= 0 && result->type == EXEC_UNKNOWN) {
		if (result->user_time > limit->time_limit
		    || result->real_time >
		    limit->time_limit * REALTIME_RATE + REALTIME_OFFSET) {
			return EXEC_TLE;
		}
	}

	if (WIFEXITED(status)) {
		if (pid == context->child_pid) {
			int exit_status = WEXITSTATUS(status);
			result->exit_status = exit_status;
			if (exit_status == 0) {
				return EXEC_SUCCESS;
			} else {
				return EXEC_FAILURE;
			}
		}
	} else if (WIFSIGNALED(status)) {
		if (pid == context->child_pid) {
			int signo = WTERMSIG(status);
			result->exit_status = signo;
			return EXEC_CRASHED;
		}
	} else if (WIFSTOPPED(status)) {
		int signo = WSTOPSIG(status);
		if (pid == context->child_pid && result->type == EXEC_UNKNOWN) {
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
		switch (signo) {
		case SIGTRAP | 0x80:
			{
				enum exec_result_type ret =
				    check_syscall(context, pid);
				if (ret != EXEC_UNKNOWN) {
					return ret;
				}
				break;
			}
		}

		// first or new process to init
		if (hash_find(context->procs, pid) == NULL) {
			/*signo == SIGSTOP
			   || status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))
			   || status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))
			   || status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) { */
			long options =
			    PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK |
			    PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD;
			DBG("options=%ld", options);
			ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)options);

			struct process_info *info =
			    malloc(sizeof(struct process_info));
			assert(info != NULL);
			info->memory_usage = 0;
			info->fake_return = false;
			info->in_syscall = false;
			hash_insert(context->procs, pid, info);
		}
	} else {
		ERR("Not exit/signaled/stopped");
		return EXEC_VIOLATION;
	}

	ptrace(PTRACE_SYSCALL, pid, 0, 0);

	return EXEC_UNKNOWN;
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

	context->start_time = time_of_day();
	for (;;) {
		enum exec_result_type result = loop_body(context);
		if (result != EXEC_UNKNOWN) {
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
	context->procs = hash_init();
	context->arg = _arg;
	context->result = _result;
	context->child_uid = 10000 + rand() % 20000;
	context->child_gid = context->child_uid;
	DBG("uid=gid=%d", context->child_uid);

	memset(context->result, 0, sizeof(struct exec_result));
	context->result->type = EXEC_UNKNOWN;

	set_iptables(context);

	context->child_pid = fork();
	assert(context->child_pid != -1);
	if (context->child_pid == 0) {
		do_child(context);
	} else {
		do_parent(context);
	}

	unset_iptables(context);
	hash_free(context->procs);
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
	srand(seed);

	gettimeofday(&tval, NULL);
	for (i = 0; i < sizeof(struct timeval) / sizeof(int); i++) {
		srand(seed ^ *((int *)&tval + i));
	}
}

void exec_init_param(const char *key, const char *value)
{
	if (!strcmp(key, "exec.realtime_rate"))
		REALTIME_RATE = atof(value);
	else if (!strcmp(key, "exec.realtime_offset"))
		REALTIME_OFFSET = atoi(value);
	else if (!strcmp(key, "exec.memory_limit_rate"))
		MEMORY_LIMIT_RATE = atof(value);
	else if (!strcmp(key, "exec.stack_limit"))
		STACK_LIMIT = atol(value);
}
