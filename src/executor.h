#pragma once
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

struct exec_limit{
	//In bytes
	long memory_limit;

	//In bytes
	long output_limit;

	//In ms
	int time_limit;

	int process_limit;
};

struct exec_arg{
	const char* command;
	char* const* argv;
	const char* cwd;
    const char* root;
	const char* input_file, *output_file, *error_file;
	struct exec_limit limit;
};

enum exec_result_type{
	EXEC_UNKNOWN=-1,
	EXEC_SUCCESS,
	EXEC_FAILURE,
	EXEC_CRASHED,
	EXEC_TLE,
	EXEC_MLE,
	EXEC_OLE,
	EXEC_VIOLATION,
	EXEC_MATH_ERROR,
	EXEC_MEM_VIOLATION,
};

struct exec_result{
	enum exec_result_type type;
	int exit_status;
	int user_time,real_time;
	long memory;
};

extern void exec_execute(const struct exec_arg *arg,struct exec_result *result);
extern void exec_init();
extern void exec_init_param(const char *key, const char *value);
