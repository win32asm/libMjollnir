cmake_minimum_required(VERSION 3.3)
project(libMjollnir)

include_directories(
        /usr/include
        /usr/include/gnutls
)

find_library(gnutls NAMES libgnutls-deb0 libgnutls)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

set(SOURCE_FILES main.c libmjollnir.h libmjollnir_int.h tor_setup.c)
add_executable(libMjollnir ${SOURCE_FILES})