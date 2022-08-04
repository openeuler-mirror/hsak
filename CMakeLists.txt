# /******************************************************************************
#  * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
#  * hsak is licensed under the Mulan PSL v2.
#  * You can use this software according to the terms and conditions of the Mulan PSL v2.
#  * You may obtain a copy of Mulan PSL v2 at:
#  *     http://license.coscl.org.cn/MulanPSL2
#  * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
#  * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
#  * PURPOSE.
#  * See the Mulan PSL v2 for more details.
#  * Author: suweifeng
#  * Create: 2022-01-10
#  * Description: Makefile for hsak
#  ******************************************************************************/

cmake_minimum_required (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
project(hsak)

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
message( STATUS "Architecture: ${ARCHITECTURE}" )
if(CONFIG_ERR_INJC STREQUAL "y")
 set(CFG_INJC "--enable-err-injc")
 message("INJECT ${CFG_INJC}")
endif()

if(CONFIG_DEBUG STREQUAL "y")
 set(CFG_DEBUG "--enable-debug")
 message("DEBUG ${CFG_DEBUG}")
endif()

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(BUILD_DIR ${PROJECT_SOURCE_DIR}/build)

set(HSAK_UIO_SRC
 ${SRC_DIR}/bdev_rw.c
 ${SRC_DIR}/bdev_rw_common.c
 ${SRC_DIR}/bdev_rw_err_injc.c
 ${SRC_DIR}/bdev_rw_poll.c
 ${SRC_DIR}/bdev_rw_rpc.c
 ${SRC_DIR}/bdev_rw_stat.c)

set(HSAK_MGR_SRC
 ${SRC_DIR}/ublock_bdev.c
 ${SRC_DIR}/ublock_rpc.c
 ${SRC_DIR}/ublock_client.c
 ${SRC_DIR}/ublock_iostat.c)
 

if(CONFIG_ERR_INJC STREQUAL "y")
 list(APPEND HSAK_UIO_SRC ${SRC_DIR}/bdev_rw_err_injc.c)
 list(APPEND HSAK_MGR_SRC ${SRC_DIR}/ublock_smart_info_err_injc.c)
endif()

set(DPDK_DIR "/usr/lib64/dpdk/pmds-22.0")

set(DPDK_LIB_DIR "${DPDK_DIR}/lib")
set(DPDK_STATIC_LIB_DIR "/usr/lib64")

set(DPDK_INC_DIR "${PROJECT_SOURCE_DIR}/dpdk_include")

add_library(
 storage_bdev_rw
 SHARED
 ${HSAK_UIO_SRC})

add_library(
 storage_ublock
 SHARED
 ${HSAK_MGR_SRC})

add_definitions(-DSPDK_CONFIG_APP_RW)

if(CONFIG_ERR_INJC STREQUAL "y")
 add_definitions(-DSPDK_CONFIG_ERR_INJC)
endif()

if(CONFIG_DEBUG STREQUAL "y")
 add_definitions(-DSPDK_CONFIG_DEBUG)
endif()

set(LIBRARY_OUTPUT_PATH ${BUILD_DIR}/lib)

link_directories(/usr/lib64)

target_include_directories(storage_bdev_rw PRIVATE
 ${PROJECT_SOURCE_DIR}/include
 ${DPDK_INC_DIR})

target_include_directories(storage_ublock PRIVATE
 ${PROJECT_SOURCE_DIR}/include
 ${DPDK_INC_DIR})

 target_compile_options(storage_bdev_rw PRIVATE -fsigned-char -Wno-deprecated-declarations -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -I${PROJECT_SOURCE_DIR}/include -Werror -Wformat -Wformat-security -D_GNU_SOURCE -fPIE -pie -fPIC -fstack-protector-strong -fno-common -DNDEBUG -O2 -D_FORTIFY_SOURCE=2 -Wall -Werror -fno-aggressive-loop-optimizations -pthread -Wno-pointer-sign -Wstrict-prototypes -Wold-style-definition -std=gnu99 -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines)
 target_compile_options(storage_ublock PRIVATE -fsigned-char -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -I${PROJECT_SOURCE_DIR}/include -Werror -Wformat -Wformat-security -D_GNU_SOURCE -fPIE -pie -fPIC -fstack-protector-strong -fno-common -DNDEBUG -O2 -D_FORTIFY_SOURCE=2 -Wall -Werror -pthread -Wno-pointer-sign -Wstrict-prototypes -Wold-style-definition -std=gnu99 -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines)


if(CONFIG_DEBUG STREQUAL "y")
 target_compile_options(storage_bdev_rw PRIVATE -g)
 target_compile_options(storage_ublock PRIVATE -g)
endif()

if(COVERAGE_ENABLE)
 message(STATUS "Enable coverage compile option")
 SET(COVERAGE_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage")
endif(COVERAGE_ENABLE)

if(ASAN_ENABLE)
 message(STATUS "Enable asan compile option")
 SET(ASAN_OPTIONS "${ASAN_OPTION} -fsanitize=address -fsanitize-recover=address")
endif(ASAN_ENABLE)

IF(CMAKE_BUILD_TYPE STREQUAL Debug)
 SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
 SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
 add_subdirectory(test)
ENDIF()

if( ${ARCHITECTURE} STREQUAL "aarch64" )
 target_compile_options(storage_bdev_rw PRIVATE -march=armv8-a)
 target_compile_options(storage_ublock PRIVATE -march=armv8-a)
else()
 target_compile_options(storage_bdev_rw PRIVATE -march=core-avx-i -m64)
 target_compile_options(storage_ublock PRIVATE -march=core-avx-i -m64)
endif()

if(NOT DEFINED CONFIG_DEBUG)
 set(CMAKE_SHARED_LINKER_FLAGS "-s")
endif()

set_target_properties(storage_bdev_rw PROPERTIES LINK_FLAGS "-fPIE -pie -fPIC -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -Wl,--whole-archive -Wl,-Bstatic -lspdk_vmd -lspdk_rdma -lspdk_event_vmd -lspdk_notify -lspdk_sock -lspdk_sock_posix -lspdk_event_sock -lspdk_bdev_nvme -lspdk_nvme -lspdk_event_bdev -lspdk_event_accel -lspdk_net -lspdk_bdev -lspdk_accel -lspdk_trace -lspdk_conf -lspdk_event -lspdk_util -lspdk_thread -lspdk_log -lspdk_jsonrpc -lspdk_json -lspdk_rpc -lspdk_env_dpdk -Wl,--no-whole-archive -Wl,--start-group -Wl,--whole-archive -Wl,-Bdynamic  ${DPDK_LIB_DIR}/librte_eal.so ${DPDK_LIB_DIR}/librte_mempool.so ${DPDK_LIB_DIR}/librte_ring.so ${DPDK_LIB_DIR}/librte_mempool_ring.so ${DPDK_LIB_DIR}/librte_bus_pci.so ${DPDK_LIB_DIR}/librte_power.so ${DPDK_LIB_DIR}/librte_mbuf.so ${DPDK_LIB_DIR}/librte_net.so ${DPDK_LIB_DIR}/librte_ethdev.so ${DPDK_LIB_DIR}/librte_telemetry.so -Wl,--end-group -Wl,--no-whole-archive")
target_link_libraries(storage_bdev_rw PRIVATE aio pthread dl rt boundscheck uuid fuse3 rdmacm ibverbs)

set_target_properties(storage_bdev_rw PROPERTIES NO_SONAME 1)

set_target_properties(storage_ublock PROPERTIES LINK_FLAGS "-fPIE -pie -fPIC -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -Wl,--whole-archive -Wl,-Bstatic -lspdk_vmd -lspdk_rdma -lspdk_event_vmd -lspdk_notify -lspdk_sock -lspdk_sock_posix -lspdk_event_sock -lspdk_bdev_nvme -lspdk_nvme -lspdk_event_bdev -lspdk_event_accel -lspdk_net -lspdk_bdev -lspdk_accel -lspdk_trace -lspdk_conf -lspdk_util -lspdk_log -lspdk_event -lspdk_jsonrpc -lspdk_json -lspdk_rpc -lspdk_env_dpdk -lspdk_thread -Wl,--no-whole-archive -Wl,--start-group -Wl,--whole-archive ${DPDK_STATIC_LIB_DIR}/librte_eal.a ${DPDK_STATIC_LIB_DIR}/librte_mempool.a ${DPDK_STATIC_LIB_DIR}/librte_ring.a ${DPDK_STATIC_LIB_DIR}/librte_bus_pci.a ${DPDK_STATIC_LIB_DIR}/librte_pci.a ${DPDK_STATIC_LIB_DIR}/librte_acl.a ${DPDK_STATIC_LIB_DIR}/librte_kvargs.a ${DPDK_STATIC_LIB_DIR}/librte_mbuf.a ${DPDK_STATIC_LIB_DIR}/librte_power.a ${DPDK_STATIC_LIB_DIR}/librte_net.a ${DPDK_STATIC_LIB_DIR}/librte_ethdev.a ${DPDK_STATIC_LIB_DIR}/librte_telemetry.a -Wl,--end-group -Wl,--no-whole-archive -Wl,-Bdynamic")

target_link_libraries(storage_ublock PRIVATE aio pthread dl rt boundscheck uuid numa fuse3 rdmacm ibverbs)

set_target_properties(storage_ublock PROPERTIES NO_SONAME 1)

if(CONFIG_DEBUG STREQUAL "y")
 target_compile_options(storage_bdev_rw_static PRIVATE -g)
endif()

# compile cmdline tools
add_subdirectory(cli)
