#pragma once
#include <stdio.h>
#include <stdlib.h>

extern const char* log_prefix();

#define LOG(fmt,args...) printf("%s [Log] " fmt "\n",log_prefix(),##args)
#define DBG(fmt,args...) printf(fmt "\n",##args)
#define ERR(fmt,args...) fprintf(stderr,"%s [Err] " fmt "\n",log_prefix(),##args)
