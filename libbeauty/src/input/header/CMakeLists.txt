set(the_description "Input Header")
add_library(beauty_input_header find_types.cpp)
set_target_properties(beauty_input_header PROPERTIES
      CXX_STANDARD 11
      CXX_EXTENSIONS NO
      LINKER_LANGUAGE CXX
)
target_link_libraries(beauty_input_header )
target_include_directories(beauty_input_header PRIVATE "${libbeauty_INCLUDE_DIRS}")
install (TARGETS beauty_input_header DESTINATION lib/beauty)
