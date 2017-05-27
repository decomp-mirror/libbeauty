export ENABLE_DEBUG_DIS64=1
export ENABLE_DEBUG_INPUT_BFD=0
export ENABLE_DEBUG_INPUT_DIS=0
export ENABLE_DEBUG_EXE=0
export ENABLE_DEBUG_ANALYSE=0
export ENABLE_DEBUG_ANALYSE_PATHS=0
export ENABLE_DEBUG_ANALYSE_PHI=0
export ENABLE_DEBUG_OUTPUT=0
export ENABLE_DEBUG_OUTPUT_LLVM=0

mkdir llvm
echo -n test10_ll:
if ../../../test/dis64 test10_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test11_ll:
if ../../../test/dis64 test11_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test12_ll:
if ../../../test/dis64 test12_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test13_ll:
if ../../../test/dis64 test13_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test14_ll:
if ../../../test/dis64 test14_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test15_ll:
if ../../../test/dis64 test15_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test16_ll:
if ../../../test/dis64 test16_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test17_ll:
if ../../../test/dis64 test17_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test18_ll:
if ../../../test/dis64 test18_ll.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi

