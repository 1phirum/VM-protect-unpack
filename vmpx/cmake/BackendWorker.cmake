include(ExternalProject)
if(NOT DEFINED VMPX_VCVARS32)
  set(VMPX_VCVARS32
      "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars32.bat"
      CACHE FILEPATH "MSVC x86 environment script")
endif()
if(NOT EXISTS "${VMPX_VCVARS32}")
  message(FATAL_ERROR "Set VMPX_VCVARS32 to an installed MSVC vcvars32.bat")
endif()
configure_file(${CMAKE_CURRENT_LIST_DIR}/worker-build.cmd.in
               ${CMAKE_BINARY_DIR}/worker-build.cmd @ONLY)
ExternalProject_Add(
  vmpx_worker
  SOURCE_DIR ${PROJECT_SOURCE_DIR}/backend
  BINARY_DIR ${CMAKE_BINARY_DIR}/backend-x86
  CONFIGURE_COMMAND "cmd" /c "${CMAKE_BINARY_DIR}/worker-build.cmd" configure
  BUILD_COMMAND "cmd" /c "${CMAKE_BINARY_DIR}/worker-build.cmd" build
  INSTALL_COMMAND ""
  BUILD_ALWAYS ON)
