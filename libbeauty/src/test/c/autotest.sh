export ENABLE_DEBUG_DIS64=1
export ENABLE_DEBUG_INPUT_BFD=0
export ENABLE_DEBUG_INPUT_DIS=0
export ENABLE_DEBUG_EXE=0
export ENABLE_DEBUG_ANALYSE=0
export ENABLE_DEBUG_ANALYSE_PATHS=0
export ENABLE_DEBUG_ANALYSE_PHI=0
export ENABLE_DEBUG_OUTPUT=1

mkdir llvm
echo -n test00:
if ../../../test/dis64 test0.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test01:
if ../../../test/dis64 test1.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test02:
if ../../../test/dis64 test2.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test03:
if ../../../test/dis64 test3.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test04:
if ../../../test/dis64 test4.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test05:
if ../../../test/dis64 test5.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test06:
if ../../../test/dis64 test6.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test07:
if ../../../test/dis64 test7.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test08:
if ../../../test/dis64 test8.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test09:
if ../../../test/dis64 test9.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test10:
if ../../../test/dis64 test10.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test11:
if ../../../test/dis64 test11.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test12:
if ../../../test/dis64 test12.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test13:
if ../../../test/dis64 test13.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test14:
if ../../../test/dis64 test14.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test15:
if ../../../test/dis64 test15.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test16:
if ../../../test/dis64 test16.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test17:
if ../../../test/dis64 test17.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test18:
if ../../../test/dis64 test18.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test19:
if ../../../test/dis64 test19.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test20:
if ../../../test/dis64 test20.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test21:
if ../../../test/dis64 test21.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test22:
if ../../../test/dis64 test22.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test23:
if ../../../test/dis64 test23.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test24:
if ../../../test/dis64 test24.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
#echo -n test25:
#if ../../../test/dis64 test25.o 2>&1 | grep -q "END - FINISHED PROCESSING"
#echo -n test26:
#if ../../../test/dis64 test26.o 2>&1 | grep -q "END - FINISHED PROCESSING"
#echo -n test27:
#if ../../../test/dis64 test27.o 2>&1 | grep -q "END - FINISHED PROCESSING"
#echo -n test28:
#if ../../../test/dis64 test28.o 2>&1 | grep -q "END - FINISHED PROCESSING"
#echo -n test29:
#if ../../../test/dis64 test29.o 2>&1 | grep -q "END - FINISHED PROCESSING"
echo -n test30:
if ../../../test/dis64 test30.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
#echo -n test31:
#if ../../../test/dis64 test31.o 2>&1 | grep -q "END - FINISHED PROCESSING"
#echo -n test32:
#if ../../../test/dis64 test32.o 2>&1 | grep -q "END - FINISHED PROCESSING"
echo -n test33:
if ../../../test/dis64 test33.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test34:
if ../../../test/dis64 test34.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test35:
if ../../../test/dis64 test35.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test36:
if ../../../test/dis64 test36.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test37:
if ../../../test/dis64 test37.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test38:
if ../../../test/dis64 test38.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test39:
if ../../../test/dis64 test39.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test40:
if ../../../test/dis64 test40.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test41:
if ../../../test/dis64 test41.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test42:
if ../../../test/dis64 test42.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test43:
if ../../../test/dis64 test43.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test44:
if ../../../test/dis64 test44.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test45:
if ../../../test/dis64 test45.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test46:
if ../../../test/dis64 test46.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test47:
if ../../../test/dis64 test47.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test48:
if ../../../test/dis64 test48.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test49:
if ../../../test/dis64 test49.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test50:
if ../../../test/dis64 test50.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test51:
if ../../../test/dis64 test51.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test52:
if ../../../test/dis64 test52.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test53:
if ../../../test/dis64 test53.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test54:
if ../../../test/dis64 test54.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test55:
if ../../../test/dis64 test55.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test56:
if ../../../test/dis64 test56.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test57:
if ../../../test/dis64 test57.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test58:
if ../../../test/dis64 test58.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test59:
if ../../../test/dis64 test59.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test60:
if ../../../test/dis64 test60.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test61:
if ../../../test/dis64 test61.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test62:
if ../../../test/dis64 test62.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test63:
if ../../../test/dis64 test63.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test64:
if ../../../test/dis64 test64.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test65:
if ../../../test/dis64 test65.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test66:
if ../../../test/dis64 test66.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test67:
if ../../../test/dis64 test67.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test68:
if ../../../test/dis64 test68.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test69:
if ../../../test/dis64 test69.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test70:
if ../../../test/dis64 test70.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test71:
if ../../../test/dis64 test71.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test72:
if ../../../test/dis64 test72.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test73:
if ../../../test/dis64 test73.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test74:
if ../../../test/dis64 test74.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test75:
if ../../../test/dis64 test75.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test76:
if ../../../test/dis64 test76.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test77:
if ../../../test/dis64 test77.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test78:
if ../../../test/dis64 test78.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test79:
if ../../../test/dis64 test79.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test80:
if ../../../test/dis64 test80.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
echo -n test81:
if ../../../test/dis64 test81.o 2>&1 | grep -q "END - FINISHED PROCESSING"
then
	echo "PASSED"
else
	echo "FAILED"
fi
