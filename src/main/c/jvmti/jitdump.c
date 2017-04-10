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

#include <elf.h>
#include <errno.h>
#include <endian.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "jitdump.h"
#include "logger.h"

static pthread_mutex_t jitdump_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *jitdump = NULL;
static void *marker = NULL;
static uint64_t code_index = 0;

int
getTimestamp(uint64_t *timestamp)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		LOG_ERROR("%s : %s", "Getting Timestamp", strerror(errno));
		return -1;
	}
	*timestamp = (uint64_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
	return 0;
}

/**
 * Get the ELF machine architecture.
 * 
 * @return ELF machine architecture on success, EM_NONE on failure
 */
static uint32_t
getElfMachine()
{
	uint32_t e_machine = EM_NONE;
	Elf64_Ehdr elf_header;
	FILE *exe = fopen("/proc/self/exe", "r");

	if (exe == NULL) {
		LOG_ERROR("%s : %s", "Reading /proc/self/exe", strerror(errno));
		return e_machine;
	}

	if (fread(&elf_header, sizeof (Elf64_Ehdr), 1, exe) != 1) {
		LOG_ERROR("%s : %s", "Reading /proc/self/exe", strerror(errno));
		goto end;
	}

	e_machine = elf_header.e_machine;

end:
	fclose(exe);
	return e_machine;
}

/**
 * Write the file header to the jitdump file.
 * 
 * @return 0 on success
 */
static int
writeFileHeader()
{
	FileHeader header;

	if (getTimestamp(&header.timestamp)) {
		return -1;
	}
	if ((header.e_machine = getElfMachine()) == EM_NONE) {
		return -1;
	}

	header.magic = (BYTE_ORDER == LITTLE_ENDIAN) ? 0x4A695444 : 0x4454694a;
	header.version = 1;
	header.size = sizeof (FileHeader);
	header.pad1 = 0;
	header.pid = getpid();
	header.flags = 0;

	if (fwrite(&header, sizeof (FileHeader), 1, jitdump) != 1) {
		return -1;
	}

	return 0;
}

/**
 * Recursively (if required) mkdir directory.
 * 
 * @param dir directory to create
 * @return 0 on success
 */
static int
mkdirs(const char *dir)
{
	struct stat stats;
	if (stat(dir, &stats)) {
		char parent[1024];
		strncpy(parent, dir, 1024);
		if (!mkdirs(dirname(parent))) {
			return mkdir(dir, 0755);
		} else {
			perror(parent);
			return -1;
		}
	}
	return 0;
}

int
open_jitdump(const char *dir)
{
	int error = -1;
	char filename[PATH_MAX];

	if (pthread_mutex_lock(&jitdump_lock)) {
		LOG_ERROR("%s : %s", "Locking Mutex", strerror(errno));
		return -1;
	}

	if (jitdump == NULL) {
		char date[16];
		char temp_dir[PATH_MAX];
		time_t rawtime;
		struct tm * timeinfo;
		long pgsz;

		if (time(&rawtime) == -1) {
			LOG_ERROR("%s : %s", "Getting raw time", strerror(errno));
			goto end;
		}
		if ((timeinfo = localtime(&rawtime)) == NULL) {
			LOG_ERROR("%s", "Getting local time");
			goto end;
		}

		strftime(date, 16, "%G%m%d-%H%M", timeinfo);
		snprintf(temp_dir, PATH_MAX, "%s/java-jit-%s.XXXXXX", dir, date);


		if (mkdirs(dir)) {
			LOG_ERROR("%s(%s) : %s", "Creating directory", dir, strerror(errno));
			goto end;
		}

		if (mkdtemp(temp_dir) == NULL) {
			LOG_ERROR("%s(%s) : %s", "Creating directory", temp_dir, strerror(errno));
			goto end;
		}

		snprintf(filename, PATH_MAX, "%s/jit-%d.dump", temp_dir, getpid());
		int fd = open(filename, O_CREAT | O_TRUNC | O_RDWR, 0666);
		if (fd == -1) {
			LOG_ERROR("%s(%s) : %s", "Creating jit dump", filename, strerror(errno));
			goto end;
		}

		if ((pgsz = sysconf(_SC_PAGESIZE)) == -1) {
			LOG_ERROR("%s : %s", "Getting page size", strerror(errno));
			close(fd);
			goto end;
		}

		if ((marker = mmap(NULL, pgsz, PROT_EXEC | PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
			LOG_ERROR("%s(%s) : %s", "Mapping jit dump", filename, strerror(errno));
			close(fd);
			goto end;
		}

		if ((jitdump = fdopen(fd, "w")) == NULL) {
			LOG_ERROR("%s(%s) : %s", "Opening jit dump", filename, strerror(errno));
			munmap(marker, 0);
			marker = NULL;
			close(fd);
			goto end;
		}

		if (writeFileHeader()) {
			LOG_ERROR("%s(%s) : %s", "Writing jit dump header", filename, strerror(errno));
			munmap(marker, 0);
			marker = NULL;
			fclose(jitdump);
			jitdump = NULL;
			goto end;
		}
		error = 0;
	} else {
		LOG_ERROR("%s %s", "Jit dump already active on process", getpid());
	}

end:
	pthread_mutex_unlock(&jitdump_lock);
	if (!error) {
		LOG_INFO("%s(%s)", "Jit dump opened", filename);
	}
	return error;
}

bool
is_jitdump_active()
{
	if (!pthread_mutex_lock(&jitdump_lock)) {
		bool result = jitdump != NULL && marker != NULL;
		pthread_mutex_unlock(&jitdump_lock);
		return result;
	}
	return true;
}

int
close_jitdump()
{
	int error = 0;

	RecordHeader close;
	close.id = JIT_CODE_CLOSE;
	close.record_size = sizeof (RecordHeader);
	getTimestamp(&close.timestamp);

	if (!pthread_mutex_lock(&jitdump_lock)) {
		if (jitdump != NULL && marker != NULL) {
			if (jitdump != NULL) {
				if (fwrite(&close, sizeof (RecordHeader), 1, jitdump) != 1) {
					LOG_ERROR("%s : %s", "Writing close record", strerror(errno));
					error = -1;
				};
				if (fclose(jitdump)) {
					LOG_ERROR("%s : %s", "Closing jit dump", strerror(errno));
					error = -1;
				} else {
					jitdump = NULL;
				}
			}

			if (marker != NULL) {
				long pgsz;
				if ((pgsz = sysconf(_SC_PAGESIZE)) == -1) {
					LOG_ERROR("%s : %s", "Getting page size", strerror(errno));
					error = -1;
				} else {
					if (munmap(marker, pgsz)) {
						LOG_ERROR("%s : %s", "Unmapping jit dump", strerror(errno));
						error = -1;
					} else {
						marker = NULL;
					}
				}
			}

			if (!error) {
				LOG_INFO("Jit dump closed");
			}
		}
		pthread_mutex_unlock(&jitdump_lock);
	}

	return error;
}

int
write_CodeLoadRecord(CodeLoadRecord *clRecord)
{
	size_t name_len = strlen(clRecord->name) + 1;
	clRecord->header.record_size = sizeof (CodeLoadRecord) - sizeof (char *) +name_len + clRecord->size;

	if (!pthread_mutex_lock(&jitdump_lock)) {
		if (jitdump != NULL) {
			clRecord->index = code_index++;
			fwrite(clRecord, sizeof (CodeLoadRecord) - sizeof (char *), 1, jitdump);
			fwrite((void *) clRecord->name, name_len, 1, jitdump);
			fwrite((void *) clRecord->address, clRecord->size, 1, jitdump);
		}
		pthread_mutex_unlock(&jitdump_lock);
	}
}

int
write_DebugInfoRecord(DebugInfoRecord *diRecord)
{
	diRecord->count = 0;
	diRecord->header.record_size = sizeof (DebugInfoRecord) - sizeof (DebugEntry *);
	for (DebugEntry *entry = diRecord->entries; entry->filename != NULL; entry++, diRecord->count++) {
		diRecord->header.record_size += (sizeof (DebugEntry) - sizeof (char *)) + strlen(entry->filename) + 1;
	}

	if (!pthread_mutex_lock(&jitdump_lock)) {
		if (jitdump != NULL) {
			fwrite(diRecord, sizeof (DebugInfoRecord) - sizeof (DebugEntry *), 1, jitdump);
			for (DebugEntry *current = diRecord->entries; current->filename != NULL; current++) {
				fwrite(current, sizeof (DebugEntry) - sizeof (char *), 1, jitdump);
				fwrite((void *) current->filename, strlen(current->filename) + 1, 1, jitdump);
			}
		}
		pthread_mutex_unlock(&jitdump_lock);
	}
}
