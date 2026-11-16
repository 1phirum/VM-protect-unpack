add_library(gui_dialogs STATIC process_dialog.cpp process_dialog.h
                               operation_dialog.cpp operation_dialog.h)
target_link_libraries(gui_dialogs PUBLIC gui_backend gui_widgets Qt6::Widgets
                                         Qt6::Concurrent)
target_include_directories(gui_dialogs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
