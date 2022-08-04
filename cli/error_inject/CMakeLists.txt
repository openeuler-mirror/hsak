# Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
# Description: make file of ublock
# Author: Zhoupengchen
# Create: 2019-2-18

cmake_minimum_required (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
set(ublock_SRC
 ${PROJECT_SOURCE_DIR}/src/ublock_bdev.c
 ${PROJECT_SOURCE_DIR}/src/ublock_rpc.c
 ${PROJECT_SOURCE_DIR}/src/ublock_client.c
 ${PROJECT_SOURCE_DIR}/src/ublock_iostat.c
 ${PROJECT_SOURCE_DIR}/src/ublock_smart_info_err_injc.c)

add_executable(libstorage-error-inject ${PROJECT_SOURCE_DIR}/cli/error_inject/ublock_error_inject.c ${PROJECT_SOURCE_DIR}/cli/ublock_cli_common.c ${ublock_SRC})

set(EXECUTABLE_OUTPUT_PATH ${BUILD_DIR}/bin)

target_include_directories(libstorage-error-inject PRIVATE
 ${PROJECT_SOURCE_DIR}/include
 ${DPDK_INC_DIR})

target_include_directories(libstorage-error-inject PRIVATE
 ../
)

target_compile_options(libstorage-error-inject PRIVATE -fsigned-char -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -I${PROJECT_SOURCE_DIR}/include -Werror -Wformat -Wformat-security -D_GNU_SOURCE -fPIE -pie -fPIC -fstack-protector-strong -fno-common -DNDEBUG -O2 -D_FORTIFY_SOURCE=2 -Wall -Werror -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -pthread -Wno-pointer-sign -Wstrict-prototypes -Wold-style-definition -Wno-implicit-fallthrough -std=gnu99)

if( ${ARCHITECTURE} STREQUAL "aarch64" )
 target_compile_options(libstorage-error-inject PRIVATE -march=armv8-a)
else()
 target_compile_options(libstorage-error-inject PRIVATE -march=core-avx-i -m64)
endif()

set_target_properties(libstorage-error-inject PROPERTIES LINK_FLAGS
 "-fPIE -pie -fPIC -Wl,-z,relro,-z,now,-z,noexecstack -Wtrampolines -Wl,--whole-archive -lspdk_vmd -lspdk_event_vmd -lspdk_notify -lspdk_sock -lspdk_sock_posix -lspdk_event_sock -lspdk_bdev_nvme -lspdk_nvme -lspdk_event_bdev -lspdk_event_accel -lspdk_net -lspdk_bdev -lspdk_accel -lspdk_trace -lspdk_conf -lspdk_util -lspdk_log -lspdk_event -lspdk_jsonrpc -lspdk_json -lspdk_rpc -lspdk_env_dpdk -lspdk_thread -Wl,--no-whole-archive -Wl,--start-group -Wl,--whole-archive ${DPDK_LIB_DIR}/librte_eal.a ${DPDK_LIB_DIR}/librte_mempool.a ${DPDK_LIB_DIR}/librte_ring.a ${DPDK_LIB_DIR}/librte_bus_pci.a ${DPDK_LIB_DIR}/librte_pci.a ${DPDK_LIB_DIR}/librte_acl.a ${DPDK_LIB_DIR}/librte_kvargs.a ${DPDK_LIB_DIR}/librte_power.a -Wl,--end-group -Wl,--no-whole-archive -lfuse3")
target_link_libraries(libstorage-error-inject PRIVATE aio pthread dl rt boundscheck numa uuid)
