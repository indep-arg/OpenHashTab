cmake_minimum_required(VERSION 3.14)

project(md4 C)

add_library(${PROJECT_NAME} STATIC md4.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
