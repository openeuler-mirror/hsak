project(hsak)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(../include)



SET(EXE ublock_iostat_llt)

add_executable(${EXE}
 ublock_iostat_llt.c)

target_link_libraries(${EXE} cunit ${BUILD_DIR}/lib/libstorage_ublock.so aio pthread dl rt boundscheck uuid numa)
