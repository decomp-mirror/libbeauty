if (NOT GENERATE_ABI_DESCRIPTOR)
  return()
endif()

set(filename "libbeauty_abi.xml")
set(path1 "${CMAKE_BINARY_DIR}/${filename}")

set(modules "${LIBBEAUTY_MODULES_PUBLIC}")
libbeauty_list_filterout(modules "libbeauty_ts")

message(STATUS "Generating ABI compliance checker configuration: ${filename}")

if (LIBBEAUTY_VCSVERSION AND NOT LIBBEAUTY_VCSVERSION STREQUAL "unknown")
  set(LIBBEAUTY_ABI_VERSION "${LIBBEAUTY_VCSVERSION}")
else()
  set(LIBBEAUTY_ABI_VERSION "${LIBBEAUTY_VERSION}")
endif()

# Headers
set(LIBBEAUTY_ABI_HEADERS "{RELPATH}/${LIBBEAUTY_INCLUDE_INSTALL_PATH}")

# Libraries
set(LIBBEAUTY_ABI_LIBRARIES "{RELPATH}/${LIBBEAUTY_LIB_INSTALL_PATH}")

set(LIBBEAUTY_ABI_SKIP_HEADERS "")
set(LIBBEAUTY_ABI_SKIP_LIBRARIES "")
foreach(mod ${LIBBEAUTY_MODULES_BUILD})
  string(REGEX REPLACE "^libbeauty_" "" mod "${mod}")
  if(NOT LIBBEAUTY_MODULE_libbeauty_${mod}_CLASS STREQUAL "PUBLIC"
      OR NOT "${LIBBEAUTY_MODULE_libbeauty_${mod}_LOCATION}" STREQUAL "${libbeauty_SOURCE_DIR}/modules/${mod}" # libbeauty_contrib
  )
    # headers
    foreach(h ${LIBBEAUTY_MODULE_libbeauty_${mod}_HEADERS})
      file(RELATIVE_PATH h "${LIBBEAUTY_MODULE_libbeauty_${mod}_LOCATION}/include" "${h}")
      list(APPEND LIBBEAUTY_ABI_SKIP_HEADERS "${h}")
    endforeach()
    # libraries
    if(TARGET libbeauty_${mod}) # libbeauty_world
      list(APPEND LIBBEAUTY_ABI_SKIP_LIBRARIES "\$<TARGET_FILE_NAME:libbeauty_${mod}>")
    endif()
  endif()
endforeach()
string(REPLACE ";" "\n    " LIBBEAUTY_ABI_SKIP_HEADERS "${LIBBEAUTY_ABI_SKIP_HEADERS}")
string(REPLACE ";" "\n    " LIBBEAUTY_ABI_SKIP_LIBRARIES "${LIBBEAUTY_ABI_SKIP_LIBRARIES}")

# Options
set(LIBBEAUTY_ABI_GCC_OPTIONS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE} -DLIBBEAUTY_ABI_CHECK=1")
string(REGEX REPLACE "([^ ]) +([^ ])" "\\1\\n    \\2" LIBBEAUTY_ABI_GCC_OPTIONS "${LIBBEAUTY_ABI_GCC_OPTIONS}")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/templates/libbeauty_abi.xml.in" "${path1}.base")
file(GENERATE OUTPUT "${path1}" INPUT "${path1}.base")
