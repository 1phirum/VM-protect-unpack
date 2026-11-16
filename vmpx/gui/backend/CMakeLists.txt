add_library(
  gui_inspection STATIC
  inspection_file.c inspection_process.c inspection.h
  ${PROJECT_SOURCE_DIR}/src/pe/hdr.c ${PROJECT_SOURCE_DIR}/src/util/bin.c)
target_include_directories(
  gui_inspection
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(gui_inspection PRIVATE psapi user32)
add_library(gui_backend STATIC command_runner.cpp command_runner.h)
target_link_libraries(gui_backend PUBLIC Qt6::Widgets gui_inspection)
target_include_directories(gui_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
