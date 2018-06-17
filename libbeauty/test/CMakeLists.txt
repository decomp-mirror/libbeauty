set(the_description "Test Tools")
add_executable(dis64 dis64.c)
set_target_properties(beauty_output_llvm PROPERTIES
      CXX_STANDARD 11
      CXX_EXTENSIONS NO
      LINKER_LANGUAGE CXX
)
target_link_libraries(dis64 -L/home/jcd/libbeauty/libbeauty/libbeauty/build/lib -L/usr/lib/llvm-5.0/lib
		-lbeauty_input_bfd -lbeauty_exe
		-lbeauty_analyse -lbeauty_output_cfg -lbeauty_output_llvm
		-lbeauty_decoder_llvm_amd64 -lbeauty_ll_inst_to_rtl
		-lbeauty_input_header
		-lLLVM-5.0
		-lstdc++ -lz -lm -ldl -lpthread -lncurses )
target_include_directories(dis64 PRIVATE "${libbeauty_INCLUDE_DIRS}")
#install (TARGETS dis64 DESTINATION bin)

add_executable(test_id test_id.c)
#set_target_properties(beauty_output_llvm PROPERTIES
#      CXX_STANDARD 11
#      CXX_EXTENSIONS NO
#      LINKER_LANGUAGE CXX
#)
target_link_libraries(test_id -L${LIBRARY_OUTPUT_PATH} -L/usr/lib/llvm-5.0/lib
		-lbeauty_input_bfd -lbeauty_exe
		-lbeauty_analyse -lbeauty_output_cfg -lbeauty_output_llvm
		-lbeauty_decoder_llvm_amd64 -lbeauty_ll_inst_to_rtl
		-lbeauty_input_header
		-lLLVM-5.0
		-lstdc++ -lz -lm -ldl -lpthread -lncurses )
target_include_directories(test_id PRIVATE "${libbeauty_INCLUDE_DIRS}")
#install (TARGETS dis64 DESTINATION bin)

add_executable(test_llvm_builder test_llvm_builder.cpp)
set_target_properties(test_llvm_builder PROPERTIES
      CXX_STANDARD 11
      CXX_EXTENSIONS NO
)
target_link_libraries(test_llvm_builder -L${LIBRARY_OUTPUT_PATH} -L/usr/lib/llvm-5.0/lib
		-lLLVM-5.0
		-lstdc++ -lz -ldl )
target_include_directories(test_llvm_builder PRIVATE "${libbeauty_INCLUDE_DIRS}")
#install (TARGETS test_llvm_builder DESTINATION bin)

