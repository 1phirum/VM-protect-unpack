add_executable(inspection_tests inspection_tests.cpp)
target_link_libraries(inspection_tests PRIVATE gui_inspection Qt6::Core)
add_test(NAME inspection_real_data COMMAND inspection_tests)
add_executable(
  gui_integration_tests
  gui_integration_tests.cpp
  ../app/main_window.cpp
  ../app/main_window.h
  ../app/window_layout.cpp
  ../app/inspections.cpp
  ../app/process_controller.cpp
  ../app/hex_controller.cpp
  ../app/actions.cpp)
target_include_directories(gui_integration_tests PRIVATE ../app)
target_link_libraries(
  gui_integration_tests PRIVATE gui_backend gui_widgets gui_dialogs gui_assets
                                Qt6::Widgets Qt6::Concurrent)
add_dependencies(gui_integration_tests vmpx_worker)
add_test(NAME gui_backend_integration COMMAND gui_integration_tests)
get_target_property(QT_QMAKE_EXECUTABLE Qt6::qmake IMPORTED_LOCATION)
execute_process(
  COMMAND "${QT_QMAKE_EXECUTABLE}" -query QT_INSTALL_PLUGINS
  OUTPUT_VARIABLE QT_PLUGIN_DIRECTORY
  OUTPUT_STRIP_TRAILING_WHITESPACE)
set_tests_properties(
  gui_backend_integration
  PROPERTIES ENVIRONMENT
             "QT_QPA_PLATFORM=offscreen;QT_PLUGIN_PATH=${QT_PLUGIN_DIRECTORY}")
