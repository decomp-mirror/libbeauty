file(GLOB old_hdrs "*.h*")
install(FILES ${old_hdrs}
    DESTINATION ${LIBBEAUTY_INCLUDE_INSTALL_PATH}/libbeauty
    COMPONENT dev)
