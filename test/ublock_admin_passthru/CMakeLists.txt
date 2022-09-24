cmake_minimum_required(VERSION 3.12)

project(hsak)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(../include)
INCLUDE_DIRECTORIES(/root/poll_time/libstorage-uio/libstorage-uio-1.0/include)

add_definitions(-DSPDK_CONFIG_APP_RW)
add_definitions(-DUNIT_TEST)

SET(EXE ublock_admin_passthru_llt)
set(hsak_SRC
 ${SRC_DIR}/ublock_bdev.c
 ${SRC_DIR}/ublock_rpc.c
 ${SRC_DIR}/ublock_client.c
 ${SRC_DIR}/ublock_iostat.c)

add_executable(${EXE}
 ublock_admin_passthru_llt.c
 ${hsak_SRC})

target_compile_options(${EXE} PRIVATE -Wno-discarded-qualifiers)
target_link_libraries(${EXE} cunit ${BUILD_DIR}/lib/libstorage_bdev_rw.so -lrte_eal -lrte_mempool -lrte_ring -lrte_mempool_ring -lrte_bus_pci pthread dl rt boundscheck uuid)
