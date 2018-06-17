set(LIBBEAUTY_APPLE_BUNDLE_NAME "libbeauty")
set(LIBBEAUTY_APPLE_BUNDLE_ID "org.libbeauty")

if(IOS)
  if (APPLE_FRAMEWORK AND BUILD_SHARED_LIBS)
    configure_file("${libbeauty_SOURCE_DIR}/platforms/ios/Info.Dynamic.plist.in"
                   "${CMAKE_BINARY_DIR}/ios/Info.plist")
  else()
    configure_file("${libbeauty_SOURCE_DIR}/platforms/ios/Info.plist.in"
                   "${CMAKE_BINARY_DIR}/ios/Info.plist")
  endif()
elseif(APPLE)
  configure_file("${libbeauty_SOURCE_DIR}/platforms/osx/Info.plist.in"
                 "${CMAKE_BINARY_DIR}/osx/Info.plist")
endif()
