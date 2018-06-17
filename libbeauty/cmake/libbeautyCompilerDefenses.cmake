# Enable build defense flags.
# Performance may be affected.
# More information:
# - https://www.owasp.org/index.php/C-Based_Toolchain_Hardening
# - https://wiki.debian.org/Hardening
# - https://wiki.gentoo.org/wiki/Hardened/Toolchain
# - https://docs.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks


set(LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON "")

macro(libbeauty_add_defense_compiler_flag option)
  libbeauty_check_flag_support(CXX "${option}" _varname "${ARGN}")
  if(${_varname})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${option}")
  endif()

  libbeauty_check_flag_support(C "${option}" _varname "${ARGN}")
  if(${_varname})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${option}")
  endif()
endmacro()

macro(libbeauty_add_defense_compiler_flag_release option)
  libbeauty_check_flag_support(CXX "${option}" _varname "${ARGN}")
  if(${_varname})
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${option}")
  endif()

  libbeauty_check_flag_support(C "${option}" _varname "${ARGN}")
  if(${_varname})
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${option}")
  endif()
endmacro()

# Define flags

if(MSVC)
  libbeauty_add_defense_compiler_flag("/GS")
  libbeauty_add_defense_compiler_flag("/sdl")
  libbeauty_add_defense_compiler_flag("/guard:cf")
  libbeauty_add_defense_compiler_flag("/w34018 /w34146 /w34244 /w34267 /w34302 /w34308 /w34509 /w34532 /w34533 /w34700 /w34789 /w34995 /w34996")
  set(LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON "${LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON} /guard:cf /dynamicbase" )
  if(NOT X86_64)
    set(LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON "${LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON} /safeseh")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCXX)
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.9")
    libbeauty_add_defense_compiler_flag("-fstack-protector")
  else()
    libbeauty_add_defense_compiler_flag("-fstack-protector-strong")
  endif()

  # These flags is added by general options: -Wformat -Wformat-security
  if(NOT CMAKE_CXX_FLAGS MATCHES "-Wformat" OR NOT CMAKE_CXX_FLAGS MATCHES "format-security")
    message(FATAL_ERROR "Defense flags: uncompatible options")
  endif()

  if(ANDROID)
    libbeauty_add_defense_compiler_flag_release("-D_FORTIFY_SOURCE=2")
    if(NOT CMAKE_CXX_FLAGS_RELEASE MATCHES "-D_FORTIFY_SOURCE=2") # TODO Check this
      libbeauty_add_defense_compiler_flag_release("-D_FORTIFY_SOURCE=1")
    endif()
  else()
    libbeauty_add_defense_compiler_flag_release("-D_FORTIFY_SOURCE=2")
  endif()

  set(LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON "${LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON} -z noexecstack -z relro -z now" )
else()
  # not supported
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
if(CMAKE_COMPILER_IS_GNUCXX)
    if(NOT CMAKE_CXX_FLAGS MATCHES "-fPIC")
      libbeauty_add_defense_compiler_flag("-fPIC")
    endif()
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
endif()

set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON}" )
set( CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON}" )
set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LIBBEAUTY_LINKER_DEFENSES_FLAGS_COMMON}" )

if(CMAKE_COMPILER_IS_GNUCXX)
  foreach(flags
          CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_DEBUG
          CMAKE_C_FLAGS CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_DEBUG)
    string(REPLACE "-O3" "-O2" ${flags} "${${flags}}")
  endforeach()
endif()
