/*
 *   Perf-JitDump-Agent: Create jitdump files supported by Linux Perf.
 *   Copyright (C) 2017 Staffan Friberg <sfriberg@kth.se>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <string.h>

#include "logger.h"

typedef struct {
	FILE *out;
	LogLevel level;
	char prefix[64];
} Logger;

static Logger logger;

const char *
log_level_name(LogLevel level)
{
	switch (level) {
		case LOG_LEVEL_OFF:
			return "OFF";
		case LOG_LEVEL_ERROR:
			return "ERROR";
		case LOG_LEVEL_WARN:
			return "ERROR";
		case LOG_LEVEL_INFO:
			return "INFO";
		case LOG_LEVEL_DEBUG:
			return "DEBUG";
		case LOG_LEVEL_TRACE:
			return "TRACE";
		default:
			return "UNKNOWN LEVEL";
	}
}

void
log_init(FILE *out, LogLevel level, const char *prefix)
{
	logger.out = out;
	logger.level = level;
	if (prefix == NULL) {
		logger.prefix[0] = '\0';
	} else {
		strncpy(logger.prefix, prefix, 64);
	}
}

void
log_msg(const char *function, int line, LogLevel level, const char *format, ...)
{
	if (level <= logger.level) {
		va_list vars;
		va_start(vars, format);
		char message[1024];
		vsnprintf(message, 1024, format, vars);
		fprintf(logger.out, "%.64s[%s:%d][%s]: %s\n", logger.prefix, function, line, log_level_name(level), message);
		va_end(vars);
	}
}