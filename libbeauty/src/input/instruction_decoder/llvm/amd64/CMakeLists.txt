set(the_description "Input Instruction Decoder")
add_library(beauty_decoder_llvm_amd64 decode_asm_X86_64.h decode_inst_disasm.h decode_inst_helper.h X86BaseInfo.h decode_asm_X86_64.cpp decode_inst.cpp)
set_target_properties(beauty_decoder_llvm_amd64 PROPERTIES SOVERSION 1)
set_target_properties(beauty_decoder_llvm_amd64 PROPERTIES VERSION "1.0.0")
set_target_properties(beauty_decoder_llvm_amd64 PROPERTIES
      CXX_STANDARD 11
      CXX_EXTENSIONS NO
      LINKER_LANGUAGE CXX
)
target_link_libraries(beauty_decoder_llvm_amd64 )
target_include_directories(beauty_decoder_llvm_amd64 PRIVATE "${libbeauty_INCLUDE_DIRS}")
install (TARGETS beauty_decoder_llvm_amd64 DESTINATION lib/beauty)
