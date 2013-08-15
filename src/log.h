#pragma once
#include <stdio.h>
#include <stdlib.h>

extern const char* log_prefix();

#define LOG(fmt,args...) fprintf(stderr, "%s [Log] " fmt "\n",log_prefix(),##args)

#ifdef DEBUG
#define DBG(fmt,args...) fprintf(stderr, fmt "\n",##args)
#else
#define DBG(ftm,args...)
#endif

#define ERR(fmt,args...) fprintf(stderr, "%s [Err] " fmt "\n",log_prefix(),##args)
