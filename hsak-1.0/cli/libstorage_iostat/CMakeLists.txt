# Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
# Description: make file of ublock
# Author: Zhoupengchen
# Create: 2019-2-18

cmake_minimum_required (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
add_executable(libstorage-iostat ${PROJECT_SOURCE_DIR}/cli/libstorage_iostat/libstorage_iostat.c)

set(EXECUTABLE_OUTPUT_PATH ${BUILD_DIR}/bin)

target_include_directories(libstorage-iostat PRIVATE
 ${PROJECT_SOURCE_DIR}/include
 ${DPDK_INC_DIR})

target_include_directories(libstorage-iostat PRIVATE
 ../
)

target_compile_options(libstorage-iostat PRIVATE -fsigned-char -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -I${PROJECT_SOURCE_DIR}/include -Werror -Wformat -Wformat-security -D_GNU_SOURCE -fPIE -pie -fPIC -fstack-protector-strong -fno-common -DNDEBUG -O2 -D_FORTIFY_SOURCE=2 -Wall -Werror -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -pthread -Wno-pointer-sign -Wstrict-prototypes -Wold-style-definition -std=gnu99)

if( ${ARCHITECTURE} STREQUAL "aarch64" )
 target_compile_options(libstorage-iostat PRIVATE -march=armv8-a)
else()
 target_compile_options(libstorage-iostat PRIVATE -march=core-avx-i -m64)
endif()

set_target_properties(libstorage-iostat PROPERTIES LINK_FLAGS
"-fPIE -pie -fPIC -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -s"
)

target_link_libraries(libstorage-iostat PRIVATE rt boundscheck)
