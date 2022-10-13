project(hsak)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(../include)
INCLUDE_DIRECTORIES(../../dpdk_include)
INCLUDE_DIRECTORIES(../../include/spdk)

SET(EXE libstorage_cuse_llt)

cmake_policy(SET CMP0015 NEW)


add_executable(${EXE} 
	libstorage_cuse_llt.c)

target_link_libraries(${EXE} cunit ${BUILD_DIR}/lib/libstorage_bdev_rw.so aio pthread dl rt boundscheck uuid numa)
