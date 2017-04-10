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
#include <jni.h>
#include <jvmti.h>
#include <jvmticmlr.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "jitdump.h"
#include "logger.h"

#define LOG_JVMTI_ERROR(jmvti, error, format, ...) log_jvmti(__func__, __LINE__, LOG_LEVEL_ERROR, jvmti, error, format, ##__VA_ARGS__)
#define LOG_JVMTI_WARN(jmvti, error, format, ...) log_jvmti(__func__, __LINE__, LOG_LEVEL_WARN, jvmti, error, format, ##__VA_ARGS__)
#define LOG_JVMTI_INFO(jmvti, error, format, ...) log_jvmti(__func__, __LINE__, LOG_LEVEL_INFO, jvmti, error, format, ##__VA_ARGS__)
#define LOG_JVMTI_DEBUG(jmvti, error, format, ...) log_jvmti(__func__, __LINE__, LOG_LEVEL_DEBUG, jvmti, error, format, ##__VA_ARGS__)
#define LOG_JVMTI_TRACE(jmvti, error, format, ...) log_jvmti(__func__, __LINE__, LOG_LEVEL_TRACE, jvmti, error, format, ##__VA_ARGS__)

static pthread_mutex_t agent_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t start = 0;
static int64_t duration = -1;

/**
 * Log JVMTI error and return the same error code
 * 
 * @param function name of function where error occurred
 * @param line line number of error
 * @param jvmti JVMTI environment to get error message
 * @param error JVMTI error code
 * @param format message format
 * @param ... message data
 * @return the supplied jvmtiError
 */
static jvmtiError
log_jvmti(const char* function, int line, LogLevel level, jvmtiEnv *jvmti, jvmtiError error, char *format, ...)
{
	char *error_name;
	char message[1024];
	va_list vars;

	va_start(vars, format);
	vsnprintf(message, 1024, format, vars);
	va_end(vars);

	if (!(*jvmti)->GetErrorName(jvmti, error, &error_name)) {
		log_msg(function, line, level, "%s : %s", message, error_name);
		(*jvmti)->Deallocate(jvmti, error_name);
	} else {
		log_msg(function, line, level, "%s : jvmtiError = %d", message, error);
	}

	return error;
}

/**
 * Get line number corresponding to a Bytecode Index (BCI) from a jvmtiLineNumberEntry array.
 * 
 * @param entries jvmtiLineNumberEntry array
 * @param count number of entries in jvmtiLineNumberEntry array
 * @param bci BCI to search for
 * @return line number (1 or greater) or -1 if not found
 */
static int
bci2line(jvmtiLineNumberEntry* entries, jint count, jint bci)
{
	if (bci >= 0) {
		for (int i = count - 1; i >= 0; i--) {
			if (bci >= entries[i].start_location) {
				return entries[i].line_number;
			}
		}
	} else if (count == 1) {
		// Only one line entry, simply return that one even if bci is invalid
		return entries[0].line_number;
	}
	return -1;
}

/**
 * Find line number for BCI in method.
 * 
 * @param jvmti JVMTI environment to use to lookup method and BCI entries
 * @param method method to search in
 * @param bci BCI to locate
 * @param line set to the found line number or -1 if not found
 * @return jvmtiError
 */
static jvmtiError
get_line_number(jvmtiEnv *jvmti, jmethodID method, jint bci, int *line)
{
	jvmtiError error = JVMTI_ERROR_NONE;
	*line = -1;
	jint count;
	jvmtiLineNumberEntry* entries;
	if (!(error = (*jvmti)->GetLineNumberTable(jvmti, method, &count, &entries))) {
		*line = bci2line(entries, count, bci);
		(*jvmti)->Deallocate(jvmti, (char *) entries);
	}
	return error;
}

/**
 * Get the full path source filename /package/name/and/Klass.java containing the method with the specified jmethodID.
 * 
 * @param jvmti JVMTI environment to use to look up required information
 * @param method method to find the source filename for
 * @param filename set to the source filename on success or NULL otherwise. Must be freed after use.
 * @return jvmtiError
 */
static jvmtiError
get_filename(jvmtiEnv *jvmti, jmethodID method, char **filename)
{
	jvmtiError error = JVMTI_ERROR_NONE;
	jclass klass;

	*filename = NULL;

	//TODO: For a large method with many inlined methods do we need to consider DeleteLocalRef to not get too many local refs
	//http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html#wp18654
	if (!(error = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &klass))) {
		char *klass_signature;
		if (!(error = (*jvmti)->GetClassSignature(jvmti, klass, &klass_signature, NULL))) {
			char *file;
			if (!(error = (*jvmti)->GetSourceFileName(jvmti, klass, &file))) {
				char *path = klass_signature[0] == 'L' ? klass_signature + 1 : klass_signature;
				char *last_slash = strrchr(path, '/');
				int path_len = last_slash == NULL ? 0 : last_slash - path;
				int length = path_len + strlen(file) + 2;
				if ((*filename = malloc(length * sizeof (char))) != NULL) {
					if (last_slash == NULL) {
						snprintf(*filename, length, "%s", file);
					} else {
						snprintf(*filename, length, "%.*s/%s", path_len, path, file);
					}
				} else {
					error = JVMTI_ERROR_OUT_OF_MEMORY;
				}
				(*jvmti)->Deallocate(jvmti, file);
			}
			(*jvmti)->Deallocate(jvmti, klass_signature);
		}
	}
	return error;
}

/**
 * Get method name for a specific jmethodID.
 * 
 * @param jvmti JVMTI environment to use to look up required information
 * @param method jmethodID of the method
 * @param method_name set to method name on success or NULL otherwise. Must be freed after use.
 * @return jvmtiError
 */
static jvmtiError
get_method_name(jvmtiEnv *jvmti, jmethodID method, char **method_name)
{
	jvmtiError error = JVMTI_ERROR_NONE;
	jclass klass;

	if (!(error = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &klass))) {
		char *klass_signature;
		if (!(error = (*jvmti)->GetClassSignature(jvmti, klass, &klass_signature, NULL))) {
			char *name;
			char *signature;
			if (!(error = (*jvmti)->GetMethodName(jvmti, method, &name, &signature, NULL))) {
				//strlen crashes on some signatures
				char *package = klass_signature[0] == 'L' ? klass_signature + 1 : klass_signature;
				int package_len = 0;
				for (; package[package_len] != ';' && package[package_len] != '\0'; package_len++) {
					if (package[package_len] == '/') {
						package[package_len] = '.';
					}
				}
				int length = package_len + strlen(name) + strlen(signature) + 2;
				*method_name = malloc(length * sizeof (char));
				snprintf(*method_name, length, "%.*s.%s%s", package_len, package, name, signature);

				(*jvmti)->Deallocate(jvmti, signature);
				(*jvmti)->Deallocate(jvmti, name);
			}
			(*jvmti)->Deallocate(jvmti, klass_signature);
		}
	}
	return error;
}

/**
 * Get available debug entries for the current method.
 * 
 * @param jvmti JVMTI environment to use to look up required information
 * @param header header of jvmtiCompiledMethodLoadRecord
 * @param method jmethodID of the current method
 * @param method_filename source code filename of the current method
 * @param method_lines jvmtiLineNumberEntry array (bci->line) for the current method
 * @param method_lines_count number of entries in the array for the current method
 * @param debug_entries JitDumpDebugEntry points to a null terminated array if successful or NULL otherwise
 * @return jvmtiError
 */
static jvmtiError
get_DebugEntries(jvmtiEnv *jvmti, jvmtiCompiledMethodLoadRecordHeader *header,
								 jmethodID method, char *method_name, char *method_filename,
								 jvmtiLineNumberEntry* method_lines, jint method_lines_count,
								 DebugEntry **debug_entries)
{
	*debug_entries = NULL;

	// check header is valid
	if (JVMTI_CMLR_MAJOR_VERSION == header->majorinfoversion
					&& JVMTI_CMLR_MINOR_VERSION == header->minorinfoversion) {

		int numpcs = 0;
		jvmtiCompiledMethodLoadRecordHeader *iterator = header;
		do {
			if (JVMTI_CMLR_INLINE_INFO == iterator->kind) {
				jvmtiCompiledMethodLoadInlineRecord *record = (jvmtiCompiledMethodLoadInlineRecord *) iterator;
				numpcs += record->numpcs;
			}
		} while (iterator = iterator->next);

		if (numpcs > 0) {

			if ((*debug_entries = calloc(numpcs + 1, sizeof (DebugEntry))) == NULL) {
				return JVMTI_ERROR_OUT_OF_MEMORY;
			}

			DebugEntry *current = *debug_entries;
			do {
				if (JVMTI_CMLR_INLINE_INFO == header->kind) {
					jvmtiCompiledMethodLoadInlineRecord *record = (jvmtiCompiledMethodLoadInlineRecord *) header;
					for (int i = 0; i < record->numpcs; i++) {
						// Only care about the method on the top of the stack which is the actual code
						int inlined_bci = record->pcinfo[i].bcis[0];
						jmethodID inlined_method = record->pcinfo[i].methods[0];
						jvmtiError error;
						int inlined_line;
						char *inlined_filename;

						//TODO: Why do we get so many BCI that are -1
						// According to perf-map-agent HotSpot does not retain line number information for inlined methods

						if (method == inlined_method) {
							// Avoid lookups and allocation if the current pcinfo is the current method
							inlined_line = bci2line(method_lines, method_lines_count, inlined_bci);
							inlined_filename = method_filename;
						} else if ((error = get_filename(jvmti, inlined_method, &inlined_filename)) == JVMTI_ERROR_NONE) {
							if (error = get_line_number(jvmti, inlined_method, inlined_bci, &inlined_line)) {
								LOG_JVMTI_DEBUG(jvmti, error, "%s : Unable to get line number for %s with bci %d", method_name, inlined_filename, inlined_bci);
								free(inlined_filename);
								continue;
							}
						} else {
							char *inline_method_name;
							if (get_method_name(jvmti, inlined_method, &inline_method_name) == JVMTI_ERROR_NONE) {
								LOG_JVMTI_DEBUG(jvmti, error, "%s : Unable to get filename for the inlined method %s", method_name, inline_method_name);
								free(inline_method_name);
							} else {
								LOG_JVMTI_DEBUG(jvmti, error, "%s : Unable to get filename for a inlined method", method_name);
							}
							continue;
						}

						// Filter out entries with bad line number information
						LOG_TRACE("DebugInfo %s : %s:%d", method_name, inlined_filename, inlined_line);
						if (inlined_line > 0) {
							current->address = (uint64_t) record->pcinfo[i].pc;
							current->discriminator = 0;
							current->line = inlined_line;
							current->filename = inlined_filename;
							current++;
						} else if (method_filename != inlined_filename) {
							free(inlined_filename);
						}
					}
				}
			} while (header = header->next);
		}
	}
	return JVMTI_ERROR_NONE;
}

/**
 * Check if the sampling duration has expired.
 * 
 * @return true if duration is larger than 0 and has expired
 */
static bool
duration_expired()
{
	if (duration > 0) {
		uint64_t current;
		if (!getTimestamp(&current)) {
			if (duration < (current - start)) {
				LOG_INFO("Duration (%lds) has expired.\n", duration / 1000000000);
				return true;
			}
		}
	}
	return false;
}

/**
 * Disable JVMTI callbacks and events.
 * 
 * @param jvmti JVMTI environment to clear
 * @return jvmtiError
 */
static jvmtiError
stop_jvmti(jvmtiEnv *jvmti)
{
	jvmtiError error = JVMTI_ERROR_NONE;
	jvmtiEventCallbacks callbacks;

	if (error = (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_DISABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL)) {
		LOG_JVMTI_ERROR(jvmti, error, "Disabling Compiled Method Load Event");
	}
	if (error = (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_DISABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, NULL)) {
		LOG_JVMTI_ERROR(jvmti, error, "Disabling Dynamic Code Generated Event");
	}

	memset(&callbacks, 0, sizeof (jvmtiEventCallbacks));
	if (error = (*jvmti)->SetEventCallbacks(jvmti, &callbacks, sizeof (jvmtiEventCallbacks))) {
		LOG_JVMTI_ERROR(jvmti, error, "Clearing Callbacks");
	}
	return error;
}

void JNICALL
method_load(jvmtiEnv *jvmti,
						jmethodID method,
						jint code_size,
						const void* code_addr,
						jint map_length,
						const jvmtiAddrLocationMap* map,
						const void* compile_info)
{
	if (duration_expired()) {
		if (pthread_mutex_lock(&agent_lock)) {
			stop_jvmti(jvmti);
			close_jitdump();
			pthread_mutex_unlock(&agent_lock);
		}
	} else {
		CodeLoadRecord cl;
		cl.header.id = JIT_CODE_LOAD;
		if (getTimestamp(&cl.header.timestamp)) {
			return;
		}
		cl.pid = getpid();
		cl.tid = pthread_self();
		cl.address = cl.virtual_address = (uint64_t) code_addr;
		cl.size = code_size;

		jvmtiError error = JVMTI_ERROR_NONE;
		char *method_name;
		if (error = get_method_name(jvmti, method, &method_name)) {
			LOG_JVMTI_ERROR(jvmti, error, "Get Method Name");
		} else {
			LOG_DEBUG("Loaded Method : %s", method_name);
			cl.name = method_name;
			jint method_lines_count;
			jvmtiLineNumberEntry* method_lines;
			if (!(*jvmti)->GetLineNumberTable(jvmti, method, &method_lines_count, &method_lines)) {

				char *method_filename;
				if (!get_filename(jvmti, method, &method_filename)) {
					if (compile_info) {
						jvmtiCompiledMethodLoadRecordHeader *header = (jvmtiCompiledMethodLoadRecordHeader*) compile_info;

						DebugEntry *entries;
						get_DebugEntries(jvmti, header, method, method_name, method_filename,
														method_lines, method_lines_count, &entries);
						if (entries != NULL) {
							DebugInfoRecord di;
							di.header.id = JIT_CODE_DEBUG_INFO;
							di.header.timestamp = cl.header.timestamp;
							di.address = cl.address;
							di.entries = entries;
							write_DebugInfoRecord(&di);
							for (DebugEntry *current = di.entries; current->filename != NULL; current++) {
								if (method_filename != current->filename) {
									free(current->filename);
								}
							}
							free(di.entries);
						}

					}
					write_CodeLoadRecord(&cl);
					free(method_filename);
				}
				(*jvmti)->Deallocate(jvmti, (char *) method_lines);
			}
			free(method_name);
		}
	}
}

void JNICALL
code_generated(jvmtiEnv *jvmti,
							 const char* method_name,
							 const void* address,
							 jint length)
{
	if (duration_expired()) {
		if (pthread_mutex_lock(&agent_lock)) {
			stop_jvmti(jvmti);
			close_jitdump();
			pthread_mutex_unlock(&agent_lock);
		}
	} else {
		LOG_DEBUG("Code Generated : %s", method_name);
		CodeLoadRecord codeload;
		codeload.header.id = JIT_CODE_LOAD;
		if (getTimestamp(&codeload.header.timestamp)) {
			return;
		}
		codeload.pid = getpid();
		codeload.tid = pthread_self();
		codeload.address = codeload.virtual_address = (uint64_t) address;
		codeload.size = length;
		codeload.name = method_name;
		write_CodeLoadRecord(&codeload);
	}
}

/**
 * Parse agent arguments.
 * 
 * @param args arguments to agent
 * @param directory will be set to the directory to where to store the JIT dump
 * @return 0 on success
 */
static int
parse_args(char *args, char *directory)
{

	snprintf(directory, PATH_MAX, "%s/%s", getenv("HOME"), ".debug/jit");
	int level = LOG_LEVEL_WARN;

	//check options
	if (args != NULL) {
		for (char *option = strtok(args, ","); option != NULL; option = strtok(NULL, ",")) {
			if (strstr(option, "verbose") != NULL) {
				sscanf(option, "verbose=%d", &level);
			} else if (strstr(option, "duration") != NULL) {
				sscanf(option, "duration=%ld", &duration);
				duration = duration * 1000000000;
				if (duration > 0 && getTimestamp(&start)) {
					return -1;
				}
			} else if (strstr(option, "directory") != NULL) {
				sscanf(option, "directory=%4096s", directory);
			}
		}
	}


	log_init(stdout, level, "jit-perf-map");
	LOG_INFO("Logging Enabled: %s", log_level_name(level));
	LOG_INFO("Duration: %lds", duration >= 0 ? duration / 1000000000 : duration);
	LOG_INFO("JitDump Output Directory: %s", directory);
	return 0;
}

/**
 * Setup JVMTI capabilities, events and callbacks.
 * 
 * @param jvmti JVMTI environment to setup
 * @return jvmtiError code
 */
static jvmtiError
setup_jvmti(jvmtiEnv *jvmti)
{
	jvmtiError error;
	jvmtiCapabilities capabilities;
	jvmtiEventCallbacks callbacks;

	memset(&capabilities, 0, sizeof (jvmtiCapabilities));
	capabilities.can_generate_compiled_method_load_events = 1;
	capabilities.can_get_source_file_name = 1;
	capabilities.can_get_line_numbers = 1;
	if (error = (*jvmti)->AddCapabilities(jvmti, &capabilities)) {
		return LOG_JVMTI_ERROR(jvmti, error, "Adding Capabilities");
	}

	memset(&callbacks, 0, sizeof (jvmtiEventCallbacks));
	callbacks.CompiledMethodLoad = method_load;
	callbacks.DynamicCodeGenerated = code_generated;
	if (error = (*jvmti)->SetEventCallbacks(jvmti, &callbacks, sizeof (jvmtiEventCallbacks))) {
		return LOG_JVMTI_ERROR(jvmti, error, "Setting Callbacks");
	}

	if (error = (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL)) {
		return LOG_JVMTI_ERROR(jvmti, error, "Enabling Compiled Method Load Event");
	}
	if (error = (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, NULL)) {
		return LOG_JVMTI_ERROR(jvmti, error, "Enabling Dynamic Code Generated Event");
	}

	return JVMTI_ERROR_NONE;
}

JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm, char *args, void *reserved)
{
	int error = 0;
	char directory[PATH_MAX];
	jint jni_error;
	jvmtiEnv *jvmti;

	if (pthread_mutex_lock(&agent_lock)) {
		LOG_ERROR("%s : %s", "Locking Mutex", strerror(errno));
		return -1;
	}

	if (is_jitdump_active()) {
		// Since jit dump is active logging must be configured as well
		LOG_ERROR("Jit dump is already active");
		error = -1;
		goto end;
	}

	if (parse_args(args, directory)) {
		error = -1;
		goto end;
	}
	LOG_INFO("Loading Agent");

	if (open_jitdump(directory)) {
		error = -1;
		goto end;
	}

	if (jni_error = (*vm)->GetEnv(vm, (void**) &jvmti, JVMTI_VERSION_1_2)) {
		LOG_ERROR("Error getting JVMTI environment: %d", jni_error);
		error = -1;
		goto end;
	}

	if (setup_jvmti(jvmti)) {
		error = -1;
		goto end;
	}

	LOG_INFO("Agent Loaded");

end:
	pthread_mutex_unlock(&agent_lock);
	return error;
}

JNIEXPORT jint JNICALL
Agent_OnAttach(JavaVM* vm, char *args, void *reserved)
{
	int error = 0;
	jvmtiEnv *jvmti;
	jint jni_error;
	jvmtiError jvmti_error;
	char directory[PATH_MAX];

	if (pthread_mutex_lock(&agent_lock)) {
		return -1;
	}

	if (is_jitdump_active()) {
		// Since jit dump is active logging must be configured as well
		LOG_ERROR("Jit dump is already active");
		error = -30;
		goto end;
	}

	if (parse_args(args, directory)) {
		error = -1;
		goto end;
	}
	LOG_INFO("Attaching Agent");

	if (open_jitdump(directory)) {
		error = -31;
		goto end;
	}

	if (jni_error = (*vm)->GetEnv(vm, (void **) &jvmti, JVMTI_VERSION_1_2)) {
		LOG_ERROR("Error getting JVMTI environment: %d\n", jni_error);
		error = -1;
		goto end;
	}

	if (setup_jvmti(jvmti)) {
		error = -1;
		goto end;
	}

	if ((jvmti_error = (*jvmti)->GenerateEvents(jvmti, JVMTI_EVENT_DYNAMIC_CODE_GENERATED)) ||
					(jvmti_error = (*jvmti)->GenerateEvents(jvmti, JVMTI_EVENT_COMPILED_METHOD_LOAD))) {
		LOG_JVMTI_ERROR(jvmti, jvmti_error, "Generating Events");
		error = -1;
	}

	// If duration is 0 exit directly
	// Looks like GenerateEvent calls are blocking so we should have written all data as when we get here
	if (duration == 0) {
		stop_jvmti(jvmti);
		close_jitdump();
	}

end:
	pthread_mutex_unlock(&agent_lock);
	if (error == 0) {
		LOG_INFO("Agent Attached");
	}
	return error;
}

JNIEXPORT void JNICALL
Agent_OnUnload(JavaVM * vm)
{
	close_jitdump();
	LOG_INFO("Agent Unloaded");
}
