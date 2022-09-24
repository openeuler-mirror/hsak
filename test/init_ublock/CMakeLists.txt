project(hsak)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(../include)



SET(EXE init_ublock_llt)

add_executable(${EXE}
 init_ublock.c)

target_link_libraries(${EXE} cunit ${BUILD_DIR}/lib/libstorage_ublock.so aio pthread dl rt boundscheck uuid numa)
