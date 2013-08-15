#include "log.h"
#include <time.h>
#include <stdio.h>

static char prefixBuffer[100];

const char *log_prefix()
{
	time_t now = time(NULL);
	struct tm *tmNow = localtime(&now);
	sprintf(prefixBuffer, "%d-%02d-%02d %02d:%02d:%02d",
		tmNow->tm_year + 1900, tmNow->tm_mon, tmNow->tm_mday,
		tmNow->tm_hour, tmNow->tm_min, tmNow->tm_sec);
	return prefixBuffer;
}
