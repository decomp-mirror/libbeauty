# platform-specific config file
configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeautyconfig.h.in" "${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}/libbeautyconfig.h")
configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeautyconfig.h.in" "${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}/libbeauty/libbeautyconfig.h")
install(FILES "${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}/libbeautyconfig.h" DESTINATION ${LIBBEAUTY_INCLUDE_INSTALL_PATH}/libbeauty COMPONENT dev)

# platform-specific config file
libbeauty_compiler_optimization_fill_cpu_config()
configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeauty_cpu_config.h.in" "${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}/libbeauty_cpu_config.h")

# ----------------------------------------------------------------------------
#  libbeauty_modules.hpp based on actual modules list
# ----------------------------------------------------------------------------
set(LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE "")

set(LIBBEAUTY_MOD_LIST ${LIBBEAUTY_MODULES_PUBLIC})
libbeauty_list_sort(LIBBEAUTY_MOD_LIST)
foreach(m ${LIBBEAUTY_MOD_LIST})
  string(TOUPPER "${m}" m)
  set(LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE "${LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE}#define HAVE_${m}\n")
endforeach()

set(LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE "${LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE}\n")

#set(LIBBEAUTY_MOD_LIST ${LIBBEAUTY_MODULES_DISABLED_USER} ${LIBBEAUTY_MODULES_DISABLED_AUTO} ${LIBBEAUTY_MODULES_DISABLED_FORCE})
#libbeauty_list_sort(LIBBEAUTY_MOD_LIST)
#foreach(m ${LIBBEAUTY_MOD_LIST})
#  string(TOUPPER "${m}" m)
#  set(LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE "${LIBBEAUTY_MODULE_DEFINITIONS_CONFIGMAKE}#undef HAVE_${m}\n")
#endforeach()

configure_file("${libbeauty_SOURCE_DIR}/cmake/templates/libbeauty_modules.hpp.in" "${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}/libbeauty/libbeauty_modules.hpp")
install(FILES "${LIBBEAUTY_CONFIG_FILE_INCLUDE_DIR}/libbeauty/libbeauty_modules.hpp" DESTINATION ${LIBBEAUTY_INCLUDE_INSTALL_PATH}/libbeauty COMPONENT dev)
