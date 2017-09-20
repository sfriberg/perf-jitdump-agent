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

#ifndef JITDUMP_H
#define JITDUMP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef enum {
		JIT_CODE_LOAD = 0,
		JIT_CODE_MOVE = 1,
		JIT_CODE_DEBUG_INFO = 2,
		JIT_CODE_CLOSE = 3,
		JIT_CODE_UNWINDING_INFO = 4
	} RecordId;

	typedef struct {
		uint32_t magic;
		uint32_t version;
		uint32_t size;
		uint32_t e_machine;
		uint32_t pad1;
		uint32_t pid;
		uint64_t timestamp;
		uint64_t flags;
	} FileHeader;

	typedef struct {
		uint32_t id;
		uint32_t record_size;
		uint64_t timestamp;
	} RecordHeader;

	typedef struct {
		RecordHeader header;
		uint32_t pid;
		uint32_t tid;
		uint64_t virtual_address;
		uint64_t address;
		uint64_t size;
		uint64_t index;
		const char *name;
	} CodeLoadRecord;

	typedef struct {
		uint64_t address;
		uint32_t line;
		uint32_t discriminator;
		char *filename;
	} DebugEntry;

	typedef struct {
		RecordHeader header;
		uint64_t address;
		uint64_t count;
		DebugEntry *entries;
	} DebugInfoRecord;

	/**
	 * Get the current timestamp.
	 * 
	 * @param timestamp set to current timestamp on success with nanosecond resolution
	 * @return 0 on success
	 */
	int
	getTimestamp(uint64_t *timestamp);

	/**
	 * Create, open and write file header to a jit dump file.
	 * The file will be located in a directory and file with the following pattern
	 * <directory>/java-jit-%G%m%d-%H%M.XXXXXX/jit-<pid>.dump.
	 * 
	 * @param dir directory to use to store jit dump information
	 * @return 0 on success
	 */
	int
	open_jitdump(const char *dir);


	/**
	 * Is a jit dump currently active
	 * @return true if active
	 */
	bool
	is_jitdump_active();

	/**
	 * 
	 * Write CloseRecord and close jit dump file.
	 * 
	 * @return 0 on success
	 */
	int
	close_jitdump();

	/**
	 * Write CodeLoadRecord to open jit dump file.
	 * Must be written after the corresponding DebugInfoRecord.
	 * 
	 * @param clRecord CodeLoadRecord to write to the jit dump file
	 * @param diRecord DebugInfoRecord to write to jit dump file, or NULL if no debug information to write
	 * @return 0 on success
	 */
	int
	write_CodeLoadRecord(CodeLoadRecord *clRecord, DebugInfoRecord *diRecord);

#ifdef __cplusplus
}
#endif

#endif /* JITDUMP_H */

