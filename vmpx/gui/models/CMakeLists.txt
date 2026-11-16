add_library(gui_models STATIC record_model.cpp record_model.h)
target_link_libraries(gui_models PUBLIC Qt6::Widgets)
target_include_directories(gui_models PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
