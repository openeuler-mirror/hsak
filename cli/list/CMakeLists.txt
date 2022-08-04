# Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
# Description: make file of ublock
# Author: Zhoupengchen
# Create: 2019-2-18

cmake_minimum_required (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
set(ublock_SRC
 ${SRC_DIR}/ublock_bdev.c
 ${SRC_DIR}/ublock_rpc.c
 ${SRC_DIR}/ublock_client.c
 ${SRC_DIR}/ublock_iostat.c)

if(CONFIG_ERR_INJC STREQUAL "y")
 list(APPEND ublock_SRC ${SRC_DIR}/ublock_smart_info_err_injc.c)
endif()

add_executable(libstorage-list ${PROJECT_SOURCE_DIR}/cli/list/ublock_cli_list.c ${PROJECT_SOURCE_DIR}/cli/ublock_cli_common.c ${ublock_SRC})

set(EXECUTABLE_OUTPUT_PATH ${BUILD_DIR}/bin)

target_include_directories(libstorage-list PRIVATE
 ${PROJECT_SOURCE_DIR}/include
 ${DPDK_INC_DIR})

target_include_directories(libstorage-list PRIVATE
 ../
)

target_compile_options(libstorage-list PRIVATE -fsigned-char -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -I${PROJECT_SOURCE_DIR}/include -Werror -Wformat -Wformat-security -D_GNU_SOURCE -fPIE -pie -fPIC -fstack-protector-strong -fno-common -DNDEBUG -O2 -D_FORTIFY_SOURCE=2 -Wall -Werror -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -pthread -Wno-pointer-sign -Wstrict-prototypes -Wold-style-definition -std=gnu99)

if( ${ARCHITECTURE} STREQUAL "aarch64" )
 target_compile_options(libstorage-list PRIVATE -march=armv8-a)
else()
 target_compile_options(libstorage-list PRIVATE -march=core-avx-i -m64)
endif()

set_target_properties(libstorage-list PROPERTIES LINK_FLAGS " -fPIE -pie -fPIC -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -Wl,--whole-archive -Wl,-Bstatic -lspdk_vmd -lspdk_rdma -lspdk_event_vmd -lspdk_notify -lspdk_sock -lspdk_sock_posix -lspdk_event_sock -lspdk_bdev_nvme -lspdk_nvme -lspdk_event_bdev -lspdk_event_accel -lspdk_net -lspdk_bdev -lspdk_accel -lspdk_trace -lspdk_conf -lspdk_util -lspdk_log -lspdk_event -lspdk_jsonrpc -lspdk_json -lspdk_rpc -lspdk_env_dpdk -lspdk_thread -Wl,--no-whole-archive -Wl,--start-group -Wl,--whole-archive ${DPDK_STATIC_LIB_DIR}/librte_eal.a ${DPDK_STATIC_LIB_DIR}/librte_mempool.a ${DPDK_STATIC_LIB_DIR}/librte_ring.a ${DPDK_STATIC_LIB_DIR}/librte_bus_pci.a ${DPDK_STATIC_LIB_DIR}/librte_pci.a ${DPDK_STATIC_LIB_DIR}/librte_acl.a ${DPDK_STATIC_LIB_DIR}/librte_kvargs.a ${DPDK_STATIC_LIB_DIR}/librte_power.a ${DPDK_STATIC_LIB_DIR}/librte_mbuf.a ${DPDK_STATIC_LIB_DIR}/librte_net.a ${DPDK_STATIC_LIB_DIR}/librte_ethdev.a ${DPDK_STATIC_LIB_DIR}/librte_telemetry.a -Wl,--end-group -Wl,--no-whole-archive -Wl,-Bdynamic -lfuse3")
target_link_libraries(libstorage-list PRIVATE aio pthread dl rt boundscheck numa uuid rdmacm ibverbs)
