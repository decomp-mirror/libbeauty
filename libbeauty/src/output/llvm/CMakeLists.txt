set(the_description "Output LLVM")
add_library(beauty_output_llvm llvm_ir.cpp mytool.cpp)
set_target_properties(beauty_output_llvm PROPERTIES SOVERSION 1)
set_target_properties(beauty_output_llvm PROPERTIES VERSION "1.0.0")
set_target_properties(beauty_output_llvm PROPERTIES
      CXX_STANDARD 11
      CXX_EXTENSIONS NO
      LINKER_LANGUAGE CXX
)
#SET_TARGET_PROPERTIES(beauty_output_llvm PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(beauty_output_llvm -L/usr/lib/llvm-5.0/lib -lLLVM-5.0 )
target_include_directories(beauty_output_llvm PRIVATE "${libbeauty_INCLUDE_DIRS}")
#target_include_directories(beauty_output_llvm PRIVATE "/home/jcd/libbeauty/libbeauty/libbeauty/include")
install (TARGETS beauty_output_llvm DESTINATION lib/beauty)
