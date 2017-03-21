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

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef enum {
		LOG_LEVEL_OFF = 0,
		LOG_LEVEL_ERROR = 1,
		LOG_LEVEL_WARN = 2,
		LOG_LEVEL_INFO = 3,
		LOG_LEVEL_DEBUG = 4,
		LOG_LEVEL_TRACE = 5
	} LogLevel;

#define LOG_ERROR(format, ...) log_msg(__func__, __LINE__, LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) log_msg(__func__, __LINE__, LOG_LEVEL_WARN, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_msg(__func__, __LINE__, LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) log_msg(__func__, __LINE__, LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define LOG_TRACE(format, ...) log_msg(__func__, __LINE__, LOG_LEVEL_TRACE, format, ##__VA_ARGS__)

	/**
	 * Get level name from LogLevel
	 * 
	 * @param level Log level to get name for
	 * @return name of level
	 */
	const char *
	log_level_name(LogLevel level);

	/**
	 * Initialize log system.
	 * 
	 * @param out FILE to send the output to
	 * @param level The lowest Log level to output
	 * @param prefix Prefix to prepend on each log message
	 */
	void
	log_init(FILE *out, LogLevel level, const char *prefix);

	/**
	 * Log formatted message at specified level.
	 * 
	 * For fewer required function parameters use LOG_<LEVEL> macros.
	 * 
	 * @param function name of function of loged information
	 * @param line line number for logged information
	 * @param level Log level of message
	 * @param format message string format description (see printf)
	 * @param ... data for message
	 */
	void
	log_msg(const char *function, int line, LogLevel level, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */

