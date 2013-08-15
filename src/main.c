#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "executor.h"

int main(int argc, char *argv[])
{
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
}
