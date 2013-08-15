#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "vector.h"
#include "executor.h"
#include "log.h"

static int time_limit = -1;
static long memory_limit = -1;
static long output_limit = -1;
static int process_limit = -1;
static char *command;
static const char *input_file = "/dev/null";
static const char *output_file = "/dev/null";
static const char *error_file = "/dev/null";
static const char *root;
static const char *cwd;

void init_param(const char *key, const char *value)
{
	if (!strcmp(key, "time_limit"))
		time_limit = atoi(value);
	else if (!strcmp(key, "memory_limit"))
		memory_limit = atol(value);
	else if (!strcmp(key, "output_limit"))
		output_limit = atol(value);
	else if (!strcmp(key, "process_limit"))
		process_limit = atoi(value);
	else if (!strcmp(key, "command"))
		command = strdup(value);
	else if (!strcmp(key, "input_file"))
		input_file = strdup(value);
	else if (!strcmp(key, "output_file"))
		output_file = strdup(value);
	else if (!strcmp(key, "error_file"))
		error_file = strdup(value);
	else if (!strcmp(key, "root"))
		root = strdup(value);
	else if (!strcmp(key, "cwd"))
		cwd = strdup(value);
}

int main(int argc, char *argv[])
{
	struct exec_arg arg;
	struct exec_result result;
	struct vector *arg_vec;
	char *arg_item;

	exec_init();

	for (;;) {
		char *line = NULL, *eq_pos;
		size_t foo = 0;
		ssize_t line_len = getline(&line, &foo, stdin);

		if (line_len == -1)
			break;

		if (line[line_len - 1] == '\n') {
			line_len--;	// Ignore \n
			line[line_len] = 0;
		}

		eq_pos = strchr(line, '=');
		if (eq_pos == NULL) {
			LOG("Ignoring line: %s", line);
		} else {
			const char *key = line;
			const char *value = eq_pos + 1;

			*eq_pos = 0;
			exec_init_param(key, value);
			init_param(key, value);
		}

		free(line);
	}

	arg.limit.memory_limit = memory_limit;
	arg.limit.time_limit = time_limit;
	arg.limit.output_limit = output_limit;
	arg.limit.process_limit = process_limit;
	arg.root = root;
	arg.cwd = cwd;
	arg.input_file = input_file;
	arg.output_file = output_file;
	arg.error_file = error_file;

	arg.command = strtok(command, " ");
	arg_vec = vector_init();
	vector_push(arg_vec, arg.command);
	while ((arg_item = strtok(NULL, " ")) != NULL) {
		vector_push(arg_vec, arg_item);
	}
	vector_push(arg_vec, NULL);

	arg.argv = (char *const *)vector_getdata(arg_vec);
	exec_execute(&arg, &result);
	printf("exit_status=%i\n", result.exit_status);
	printf("user_time=%i\n", result.user_time);
	printf("real_time=%i\n", result.real_time);
	printf("memory=%ld\n", result.memory);
	switch (result.type) {
	case EXEC_UNKNOWN:
		ERR("result.type=UNKNOWN");
		return 1;
	case EXEC_SUCCESS:
		puts("type=SUCCESS");
		break;
	case EXEC_FAILURE:
		puts("type=FAILURE");
		break;
	case EXEC_CRASHED:
		puts("type=CRASHED");
		break;
	case EXEC_MLE:
		puts("type=MLE");
		break;
	case EXEC_TLE:
		puts("type=TLE");
		break;
	case EXEC_OLE:
		puts("type=OLE");
		break;
	case EXEC_MATH_ERROR:
		puts("type=MATH_ERROR");
		break;
	case EXEC_MEM_VIOLATION:
		puts("type=MEM_VIOLATION");
		break;
	case EXEC_VIOLATION:
		puts("tyep=VIOLATION");
		break;
	}
	return 0;

	/*
	   system("rm -f test");
	   system("g++ -O2 -o test test.cpp");
	   system("cp test /var/chroot/work/test");

	   exec_init();

	   struct exec_arg *arg = malloc(sizeof(struct exec_arg));
	   arg->command = "./test";
	   char **_argv = malloc(sizeof(char *[2]));
	   _argv[0] = "test";
	   _argv[1] = NULL;
	   arg->argv = _argv;
	   arg->cwd = "/work";
	   arg->root = "/var/chroot";
	   arg->input_file = "./0";
	   arg->output_file = "./1";
	   arg->error_file = "./2";
	   arg->limit.memory_limit = 1024 * 1024 * 100;
	   arg->limit.time_limit = 10000;
	   arg->limit.output_limit = 1024 * 1024;
	   arg->limit.process_limit = 10;
	   struct exec_result *result = malloc(sizeof(struct exec_result));
	   exec_execute(arg, result);
	   printf
	   ("Type:%d\nExitStatus:%d\nUserTime:%d\nRealTime:%d\nMemory:%lld\n",
	   result->type, result->exit_status, result->user_time,
	   result->real_time, result->memory);
	   puts("stdout:");
	   system("cat /var/chroot/work/1");
	   puts("stderr:");
	   system("cat /var/chroot/work/2");
	   return 0;
	 */
}
