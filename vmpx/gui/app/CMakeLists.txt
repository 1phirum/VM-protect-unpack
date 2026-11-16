qt_add_executable(
  vmprotect_unpack
  WIN32
  main.cpp
  main_window.cpp
  main_window.h
  window_layout.cpp
  inspections.cpp
  process_controller.cpp
  hex_controller.cpp
  actions.cpp)
target_link_libraries(
  vmprotect_unpack
  PRIVATE gui_backend
          gui_widgets
          gui_dialogs
          gui_assets
          Qt6::Widgets
          Qt6::Svg
          Qt6::Concurrent)
add_dependencies(vmprotect_unpack vmpx_worker)
set_target_properties(vmprotect_unpack PROPERTIES OUTPUT_NAME
                                                  "VM protect unpack")
if(MINGW)
  target_compile_options(vmprotect_unpack PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_custom_command(
  TARGET vmprotect_unpack
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${PROJECT_SOURCE_DIR}/gui/assets"
          "$<TARGET_FILE_DIR:vmprotect_unpack>/assets")
