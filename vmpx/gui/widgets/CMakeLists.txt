add_library(gui_widgets STATIC inspector_page.cpp inspector_page.h ui_icons.cpp
                               ui_icons.h navigation_delegate.cpp navigation_delegate.h
                               desktop_splitter.cpp desktop_splitter.h)
target_link_libraries(gui_widgets PUBLIC gui_models Qt6::Widgets)
target_include_directories(gui_widgets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
