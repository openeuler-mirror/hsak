# Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
# Description: make file of ublock
# Author: Zhoupengchen
# Create: 2019-2-18

cmake_minimum_required (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})

if(CONFIG_ERR_INJC STREQUAL "y")
 add_subdirectory(error_inject)
endif()
add_subdirectory(libstorage_iostat)
add_subdirectory(shut_down)
add_subdirectory(iostat_enable)
add_subdirectory(list)
add_subdirectory(rw)
