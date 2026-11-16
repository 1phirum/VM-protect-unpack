cmake_minimum_required(VERSION 3.24)
project(
  VMProtectUnpack
  VERSION 1.0.0
  LANGUAGES C CXX)
if(NOT WIN32)
  message(FATAL_ERROR "VM protect unpack requires Windows")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
include(CTest)
add_subdirectory(cmake)
add_subdirectory(gui)
