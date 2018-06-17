if(WITH_ITT)
  if(BUILD_ITT)
    add_subdirectory("${libbeauty_SOURCE_DIR}/3rdparty/ittnotify")
    set(ITT_INCLUDE_DIR "${libbeauty_SOURCE_DIR}/3rdparty/ittnotify/include")
    set(ITT_INCLUDE_DIRS "${ITT_INCLUDE_DIR}")
    set(ITT_LIBRARIES "ittnotify")
    set(HAVE_ITT 1)
  else()
    #TODO
  endif()
endif()

set(LIBBEAUTY_TRACE 1)
