# --------------------------------------------------------------------------------------------
#  Installation for CMake Module:  libbeautyConfig.cmake
#  Part 1/3: ${BIN_DIR}/libbeautyConfig.cmake              -> For use *without* "make install"
#  Part 2/3: ${BIN_DIR}/unix-install/libbeautyConfig.cmake -> For use with "make install"
#  Part 3/3: ${BIN_DIR}/win-install/libbeautyConfig.cmake  -> For use within binary installers/packages
# -------------------------------------------------------------------------------------------

if(INSTALL_TO_MANGLED_PATHS)
  set(libbeauty_USE_MANGLED_PATHS_CONFIGCMAKE TRUE)
else()
  set(libbeauty_USE_MANGLED_PATHS_CONFIGCMAKE FALSE)
endif()

if(HAVE_CUDA)
  libbeauty_cmake_configure("${CMAKE_CURRENT_LIST_DIR}/templates/libbeautyConfig-CUDA.cmake.in" CUDA_CONFIGCMAKE @ONLY)
endif()

if(ANDROID)
  if(NOT ANDROID_NATIVE_API_LEVEL)
    set(libbeauty_ANDROID_NATIVE_API_LEVEL_CONFIGCMAKE 0)
  else()
    set(libbeauty_ANDROID_NATIVE_API_LEVEL_CONFIGCMAKE "${ANDROID_NATIVE_API_LEVEL}")
  endif()
  libbeauty_cmake_configure("${CMAKE_CURRENT_LIST_DIR}/templates/libbeautyConfig-ANDROID.cmake.in" ANDROID_CONFIGCMAKE @ONLY)
endif()

set(LIBBEAUTY_MODULES_CONFIGCMAKE ${LIBBEAUTY_MODULES_PUBLIC})

if(BUILD_FAT_JAVA_LIB AND HAVE_libbeauty_java)
  list(APPEND LIBBEAUTY_MODULES_CONFIGCMAKE libbeauty_java)
endif()

# -------------------------------------------------------------------------------------------
#  Part 1/3: ${BIN_DIR}/libbeautyConfig.cmake              -> For use *without* "make install"
# -------------------------------------------------------------------------------------------
set(libbeauty_INCLUDE_DIRS_CONFIGCMAKE "\"${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}\" \"${libbeauty_SOURCE_DIR}/include\" \"${libbeauty_SOURCE_DIR}/include/libbeauty\"")

foreach(m ${LIBBEAUTY_MODULES_BUILD})
  if(EXISTS "${LIBBEAUTY_MODULE_${m}_LOCATION}/include")
    set(libbeauty_INCLUDE_DIRS_CONFIGCMAKE "${libbeauty_INCLUDE_DIRS_CONFIGCMAKE} \"${LIBBEAUTY_MODULE_${m}_LOCATION}/include\"")
  endif()
endforeach()

#export(TARGETS ${libbeautyModules_TARGETS} FILE "${CMAKE_BINARY_DIR}/libbeautyModules.cmake")

if(TARGET ippicv AND NOT BUILD_SHARED_LIBS)
  set(USE_IPPILIBBEAUTY TRUE)
  file(RELATIVE_PATH IPPILIBBEAUTY_INSTALL_PATH_RELATIVE_CONFIGCMAKE "${CMAKE_BINARY_DIR}" "${IPPILIBBEAUTY_LOCATION_PATH}")
  libbeauty_cmake_configure("${CMAKE_CURRENT_LIST_DIR}/templates/libbeautyConfig-IPPILIBBEAUTY.cmake.in" IPPILIBBEAUTY_CONFIGCMAKE @ONLY)
else()
  set(USE_IPPILIBBEAUTY FALSE)
endif()

if(TARGET ippiw AND NOT BUILD_SHARED_LIBS AND IPPIW_INSTALL_PATH)
  set(USE_IPPIW TRUE)
  file(RELATIVE_PATH IPPIW_INSTALL_PATH_RELATIVE_CONFIGCMAKE "${CMAKE_BINARY_DIR}" "${IPPIW_LOCATION_PATH}")
  libbeauty_cmake_configure("${CMAKE_CURRENT_LIST_DIR}/templates/libbeautyConfig-IPPIW.cmake.in" IPPIW_CONFIGCMAKE @ONLY)
else()
  set(USE_IPPIW FALSE)
endif()

libbeauty_cmake_hook(PRE_CMAKE_CONFIG_BUILD)
configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeautyConfig.cmake.in" "${CMAKE_BINARY_DIR}/libbeautyConfig.cmake" @ONLY)
#support for version checking when finding libbeauty. find_package(libbeauty 2.3.1 EXACT) should now work.
configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeautyConfig-version.cmake.in" "${CMAKE_BINARY_DIR}/libbeautyConfig-version.cmake" @ONLY)

# --------------------------------------------------------------------------------------------
#  Part 2/3: ${BIN_DIR}/unix-install/libbeautyConfig.cmake -> For use *with* "make install"
# -------------------------------------------------------------------------------------------
file(RELATIVE_PATH libbeauty_INSTALL_PATH_RELATIVE_CONFIGCMAKE "${CMAKE_INSTALL_PREFIX}/${LIBBEAUTY_CONFIG_INSTALL_PATH}/" ${CMAKE_INSTALL_PREFIX})
set(libbeauty_INCLUDE_DIRS_CONFIGCMAKE "\"\${libbeauty_INSTALL_PATH}/${LIBBEAUTY_INCLUDE_INSTALL_PATH}\" \"\${libbeauty_INSTALL_PATH}/${LIBBEAUTY_INCLUDE_INSTALL_PATH}/libbeauty\"")

if(USE_IPPILIBBEAUTY)
  file(RELATIVE_PATH IPPILIBBEAUTY_INSTALL_PATH_RELATIVE_CONFIGCMAKE "${CMAKE_INSTALL_PREFIX}" "${IPPILIBBEAUTY_INSTALL_PATH}")
  libbeauty_cmake_configure("${CMAKE_CURRENT_LIST_DIR}/templates/libbeautyConfig-IPPILIBBEAUTY.cmake.in" IPPILIBBEAUTY_CONFIGCMAKE @ONLY)
endif()
if(USE_IPPIW)
  file(RELATIVE_PATH IPPIW_INSTALL_PATH_RELATIVE_CONFIGCMAKE "${CMAKE_INSTALL_PREFIX}" "${IPPIW_INSTALL_PATH}")
  libbeauty_cmake_configure("${CMAKE_CURRENT_LIST_DIR}/templates/libbeautyConfig-IPPIW.cmake.in" IPPIW_CONFIGCMAKE @ONLY)
endif()

function(libbeauty_gen_config TMP_DIR NESTED_PATH ROOT_NAME)
  libbeauty_path_join(__install_nested "${LIBBEAUTY_CONFIG_INSTALL_PATH}" "${NESTED_PATH}")
  libbeauty_path_join(__tmp_nested "${TMP_DIR}" "${NESTED_PATH}")

  file(RELATIVE_PATH libbeauty_INSTALL_PATH_RELATIVE_CONFIGCMAKE "${CMAKE_INSTALL_PREFIX}/${__install_nested}" "${CMAKE_INSTALL_PREFIX}/")

  libbeauty_cmake_hook(PRE_CMAKE_CONFIG_INSTALL)
  configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeautyConfig-version.cmake.in" "${TMP_DIR}/libbeautyConfig-version.cmake" @ONLY)

  configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeautyConfig.cmake.in" "${__tmp_nested}/libbeautyConfig.cmake" @ONLY)
#  install(EXPORT libbeautyModules DESTINATION "${__install_nested}" FILE libbeautyModules.cmake COMPONENT dev)
  install(FILES
      "${TMP_DIR}/libbeautyConfig-version.cmake"
      "${__tmp_nested}/libbeautyConfig.cmake"
      DESTINATION "${__install_nested}" COMPONENT dev)

  if(ROOT_NAME)
    # Root config file
    configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/${ROOT_NAME}" "${TMP_DIR}/libbeautyConfig.cmake" @ONLY)
    install(FILES
        "${TMP_DIR}/libbeautyConfig-version.cmake"
        "${TMP_DIR}/libbeautyConfig.cmake"
        DESTINATION "${LIBBEAUTY_CONFIG_INSTALL_PATH}" COMPONENT dev)
  endif()
endfunction()

if((CMAKE_HOST_SYSTEM_NAME MATCHES "Linux" OR UNIX) AND NOT ANDROID)
  libbeauty_gen_config("${CMAKE_BINARY_DIR}/unix-install" "" "")
endif()

if(ANDROID)
  libbeauty_gen_config("${CMAKE_BINARY_DIR}/unix-install" "abi-${ANDROID_NDK_ABI_NAME}" "libbeautyConfig.root-ANDROID.cmake.in")
  install(FILES "${libbeauty_SOURCE_DIR}/platforms/android/android.toolchain.cmake" DESTINATION "${LIBBEAUTY_CONFIG_INSTALL_PATH}" COMPONENT dev)
endif()

# --------------------------------------------------------------------------------------------
#  Part 3/3: ${BIN_DIR}/win-install/libbeautyConfig.cmake  -> For use within binary installers/packages
# --------------------------------------------------------------------------------------------
if(WIN32)
  if(CMAKE_HOST_SYSTEM_NAME MATCHES Windows)
    if(BUILD_SHARED_LIBS)
      set(_lib_suffix "lib")
    else()
      set(_lib_suffix "staticlib")
    endif()
    libbeauty_gen_config("${CMAKE_BINARY_DIR}/win-install" "${libbeauty_INSTALL_BINARIES_PREFIX}${_lib_suffix}" "libbeautyConfig.root-WIN32.cmake.in")
  else()
    libbeauty_gen_config("${CMAKE_BINARY_DIR}/win-install" "" "")
  endif()
endif()
