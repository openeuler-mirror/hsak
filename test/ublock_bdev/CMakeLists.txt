cmake_minimum_required(VERSION 3.12)

project(hsak)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(../include)

add_definitions(-DSPDK_CONFIG_APP_RW)

SET(EXE ublock_bdev_llt)

add_executable(${EXE}
	    ublock_bdev_llt.c
	        )

target_compile_options(${EXE} PRIVATE -Wno-discarded-qualifiers)
target_link_libraries(${EXE} cunit ${BUILD_DIR}/lib/libstorage_ublock.so aio pthread dl rt boundscheck uuid numa)
