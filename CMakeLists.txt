cmake_minimum_required (VERSION 3.5.2)

project (perf-jitdump-agent)
set(perf-jitdump-agent_VERSION_MAJOR 1)
set(perf-jitdump-agent_VERSION_MINOR 0)

LIST(APPEND CMAKE_CXX_FLAGS "--std=gnu99")
LIST(APPEND CMAKE_C_FLAGS "--std=gnu99")

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR})
set(C_SOURCE_DIR src/main/c)

find_package(JNI REQUIRED)
INCLUDE_DIRECTORIES(${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})

add_library(perfjitdump SHARED ${C_SOURCE_DIR}/jvmti/perf-jitdump-agent.c ${C_SOURCE_DIR}/jvmti/jitdump.c ${C_SOURCE_DIR}/jvmti/logger.c)
set_property(TARGET perfjitdump PROPERTY C_STANDARD 99)
set_property(TARGET perfjitdump PROPERTY CXX_STANDARD 98)

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic")
endif()

# Installation, by default to local directory named jitdump
set(CMAKE_INSTALL_PREFIX ../jitdump)

install(DIRECTORY ${PROJECT_BINARY_DIR}/lib
  DESTINATION .)

install(FILES ${PROJECT_BINARY_DIR}/Perf-JitDump-Agent.jar
  DESTINATION ./lib)

install(TARGETS  perfjitdump
  LIBRARY DESTINATION ./lib)

install(FILES  src/main/bash/jitdump src/main/bash/jitdump-record
  DESTINATION ./bin
  PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ)


