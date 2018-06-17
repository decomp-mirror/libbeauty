if(ANDROID)
  # --------------------------------------------------------------------------------------------
  #  Installation for Android ndk-build makefile:  libbeauty.mk
  #  Part 1/2: ${BIN_DIR}/libbeauty.mk              -> For use *without* "make install"
  #  Part 2/2: ${BIN_DIR}/unix-install/libbeauty.mk -> For use with "make install"
  # -------------------------------------------------------------------------------------------

  # build type
  if(BUILD_SHARED_LIBS)
    set(LIBBEAUTY_LIBTYPE_CONFIGMAKE "SHARED")
  else()
    set(LIBBEAUTY_LIBTYPE_CONFIGMAKE "STATIC")
  endif()

  if(BUILD_FAT_JAVA_LIB)
    set(LIBBEAUTY_LIBTYPE_CONFIGMAKE "SHARED")
    set(LIBBEAUTY_STATIC_LIBTYPE_CONFIGMAKE "STATIC")
  else()
    set(LIBBEAUTY_STATIC_LIBTYPE_CONFIGMAKE ${LIBBEAUTY_LIBTYPE_CONFIGMAKE})
  endif()

  # build the list of libbeauty libs and dependencies for all modules
  libbeauty_get_all_libs(LIBBEAUTY_MODULES LIBBEAUTY_EXTRA_COMPONENTS LIBBEAUTY_3RDPARTY_COMPONENTS)

  # list -> string
  foreach(_var LIBBEAUTY_MODULES LIBBEAUTY_EXTRA_COMPONENTS LIBBEAUTY_3RDPARTY_COMPONENTS)
    set(var "${_var}_CONFIGMAKE")
    set(${var} "")
    foreach(lib ${${_var}})
      set(lib_name "${lib}")
      if(TARGET ${lib})
        get_target_property(_output ${lib} IMPORTED_LOCATION)
        if(NOT _output)
          get_target_property(output_name ${lib} OUTPUT_NAME)
          if(output_name)
            set(lib_name "${output_name}")
          endif()
        else()
          libbeauty_get_libname(lib_name "${_output}")
        endif()
      endif()
      set(${var} "${${var}} ${lib_name}")
    endforeach()
    string(STRIP "${${var}}" ${var})
  endforeach()

  # replace 'libbeauty_<module>' -> '<module>''
  string(REPLACE "libbeauty_" "" LIBBEAUTY_MODULES_CONFIGMAKE "${LIBBEAUTY_MODULES_CONFIGMAKE}")

  if(BUILD_FAT_JAVA_LIB)
    set(LIBBEAUTY_LIBS_CONFIGMAKE java3)
  else()
    set(LIBBEAUTY_LIBS_CONFIGMAKE "${LIBBEAUTY_MODULES_CONFIGMAKE}")
  endif()

  # -------------------------------------------------------------------------------------------
  #  Part 1/2: ${BIN_DIR}/libbeauty.mk              -> For use *without* "make install"
  # -------------------------------------------------------------------------------------------
  set(LIBBEAUTY_INCLUDE_DIRS_CONFIGCMAKE "\"${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}\" \"${libbeauty_SOURCE_DIR}/include\" \"${libbeauty_SOURCE_DIR}/include/libbeauty\"")
  set(LIBBEAUTY_BASE_INCLUDE_DIR_CONFIGCMAKE "\"${libbeauty_SOURCE_DIR}\"")
  set(LIBBEAUTY_LIBS_DIR_CONFIGCMAKE         "\$(LIBBEAUTY_THIS_DIR)/lib/\$(LIBBEAUTY_TARGET_ARCH_ABI)")
  set(LIBBEAUTY_LIBS_ARCHIVE_DIR_CONFIGCMAKE "\$(LIBBEAUTY_THIS_DIR)/lib/\$(LIBBEAUTY_TARGET_ARCH_ABI)")
  set(LIBBEAUTY_3RDPARTY_LIBS_DIR_CONFIGCMAKE "\$(LIBBEAUTY_THIS_DIR)/3rdparty/lib/\$(LIBBEAUTY_TARGET_ARCH_ABI)")

  configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeauty.mk.in" "${CMAKE_BINARY_DIR}/libbeauty.mk" @ONLY)
  configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeauty-abi.mk.in" "${CMAKE_BINARY_DIR}/libbeauty-${ANDROID_NDK_ABI_NAME}.mk" @ONLY)

  # -------------------------------------------------------------------------------------------
  #  Part 2/2: ${BIN_DIR}/unix-install/libbeauty.mk -> For use with "make install"
  # -------------------------------------------------------------------------------------------
  set(LIBBEAUTY_INCLUDE_DIRS_CONFIGCMAKE "\"\$(LOCAL_PATH)/\$(LIBBEAUTY_THIS_DIR)/include/libbeauty\" \"\$(LOCAL_PATH)/\$(LIBBEAUTY_THIS_DIR)/include\"")
  set(LIBBEAUTY_BASE_INCLUDE_DIR_CONFIGCMAKE "")
  set(LIBBEAUTY_LIBS_DIR_CONFIGCMAKE         "\$(LIBBEAUTY_THIS_DIR)/../libs/\$(LIBBEAUTY_TARGET_ARCH_ABI)")
  set(LIBBEAUTY_LIBS_ARCHIVE_DIR_CONFIGCMAKE "\$(LIBBEAUTY_THIS_DIR)/../staticlibs/\$(LIBBEAUTY_TARGET_ARCH_ABI)")
  set(LIBBEAUTY_3RDPARTY_LIBS_DIR_CONFIGCMAKE "\$(LIBBEAUTY_THIS_DIR)/../3rdparty/libs/\$(LIBBEAUTY_TARGET_ARCH_ABI)")

  configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeauty.mk.in" "${CMAKE_BINARY_DIR}/unix-install/libbeauty.mk" @ONLY)
  configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeauty-abi.mk.in" "${CMAKE_BINARY_DIR}/unix-install/libbeauty-${ANDROID_NDK_ABI_NAME}.mk" @ONLY)
  install(FILES ${CMAKE_BINARY_DIR}/unix-install/libbeauty.mk DESTINATION ${LIBBEAUTY_CONFIG_INSTALL_PATH} COMPONENT dev)
  install(FILES ${CMAKE_BINARY_DIR}/unix-install/libbeauty-${ANDROID_NDK_ABI_NAME}.mk DESTINATION ${LIBBEAUTY_CONFIG_INSTALL_PATH} COMPONENT dev)
endif(ANDROID)
