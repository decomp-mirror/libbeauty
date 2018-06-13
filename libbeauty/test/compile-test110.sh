clang-5.0 -I../include -I/usr/include/llvm-c-5.0 -I/usr/include/llvm-5.0 -c -O0 -emit-llvm -o test110.bc test110.c
llvm-dis-5.0 test110.bc
