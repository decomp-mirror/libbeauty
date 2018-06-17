# ----------------------------------------------------------------------------
# Detect Microsoft compiler:
# ----------------------------------------------------------------------------
if(CMAKE_CL_64)
    set(MSVC64 1)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_COMPILER_IS_GNUCXX 1)
  set(CMAKE_COMPILER_IS_CLANGCXX 1)
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_COMPILER_IS_GNUCC 1)
  set(CMAKE_COMPILER_IS_CLANGCC 1)
endif()
if("${CMAKE_CXX_COMPILER};${CMAKE_C_COMPILER};${CMAKE_CXX_COMPILER_LAUNCHER}" MATCHES "ccache")
  set(CMAKE_COMPILER_IS_CCACHE 1)
endif()

# ----------------------------------------------------------------------------
# Detect Intel ICC compiler -- for -fPIC in 3rdparty ( UNIX ONLY ):
#  see  include/libbeauty/cxtypes.h file for related   ICC & LIBBEAUTY_ICC defines.
# NOTE: The system needs to determine if the '-fPIC' option needs to be added
#  for the 3rdparty static libs being compiled.  The CMakeLists.txt files
#  in 3rdparty use the LIBBEAUTY_ICC definition being set here to determine if
#  the -fPIC flag should be used.
# ----------------------------------------------------------------------------
if(UNIX)
  if  (__ICL)
    set(LIBBEAUTY_ICC   __ICL)
  elseif(__ICC)
    set(LIBBEAUTY_ICC   __ICC)
  elseif(__ECL)
    set(LIBBEAUTY_ICC   __ECL)
  elseif(__ECC)
    set(LIBBEAUTY_ICC   __ECC)
  elseif(__INTEL_COMPILER)
    set(LIBBEAUTY_ICC   __INTEL_COMPILER)
  elseif(CMAKE_C_COMPILER MATCHES "icc")
    set(LIBBEAUTY_ICC   icc_matches_c_compiler)
  endif()
endif()

if(MSVC AND CMAKE_C_COMPILER MATCHES "icc|icl")
  set(LIBBEAUTY_ICC   __INTEL_COMPILER_FOR_WINDOWS)
endif()

if(NOT DEFINED CMAKE_CXX_COMPILER_VERSION)
  message(WARNING "Compiler version is not available: CMAKE_CXX_COMPILER_VERSION is not set")
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
  if(WIN32)
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} -dumpmachine
              OUTPUT_VARIABLE LIBBEAUTY_GCC_TARGET_MACHINE
              OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(LIBBEAUTY_GCC_TARGET_MACHINE MATCHES "amd64|x86_64|AMD64")
      set(MINGW64 1)
    endif()
  endif()
endif()

if(MSVC64 OR MINGW64)
  set(X86_64 1)
elseif(MINGW OR (MSVC AND NOT CMAKE_CROSSCOMPILING))
  set(X86 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set(X86_64 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686.*|i386.*|x86.*|amd64.*|AMD64.*")
  set(X86 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm.*|ARM.*)")
  set(ARM 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*)")
  set(AARCH64 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(powerpc|ppc)64le")
  set(PPC64LE 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(powerpc|ppc)64")
  set(PPC64 1)
endif()

# Workaround for 32-bit operating systems on 64-bit x86_64 processor
if(X86_64 AND CMAKE_SIZEOF_VOID_P EQUAL 4 AND NOT FORCE_X86_64)
  message(STATUS "sizeof(void) = 4 on x86 / x86_64 processor. Assume 32-bit compilation mode (X86=1)")
  unset(X86_64)
  set(X86 1)
endif()

# Similar code exists in libbeautyConfig.cmake
if(NOT DEFINED libbeauty_STATIC)
  # look for global setting
  if(NOT DEFINED BUILD_SHARED_LIBS OR BUILD_SHARED_LIBS)
    set(libbeauty_STATIC OFF)
  else()
    set(libbeauty_STATIC ON)
  endif()
endif()

if(DEFINED libbeauty_ARCH AND DEFINED libbeauty_RUNTIME)
  # custom overridden values
elseif(MSVC)
  if(CMAKE_CL_64)
    set(libbeauty_ARCH x64)
  elseif((CMAKE_GENERATOR MATCHES "ARM") OR ("${arch_hint}" STREQUAL "ARM") OR (CMAKE_VS_EFFECTIVE_PLATFORMS MATCHES "ARM|arm"))
    # see Modules/CmakeGenericSystem.cmake
    set(libbeauty_ARCH ARM)
  else()
    set(libbeauty_ARCH x86)
  endif()
  if(MSVC_VERSION EQUAL 1400)
    set(libbeauty_RUNTIME vc8)
  elseif(MSVC_VERSION EQUAL 1500)
    set(libbeauty_RUNTIME vc9)
  elseif(MSVC_VERSION EQUAL 1600)
    set(libbeauty_RUNTIME vc10)
  elseif(MSVC_VERSION EQUAL 1700)
    set(libbeauty_RUNTIME vc11)
  elseif(MSVC_VERSION EQUAL 1800)
    set(libbeauty_RUNTIME vc12)
  elseif(MSVC_VERSION EQUAL 1900)
    set(libbeauty_RUNTIME vc14)
  elseif(MSVC_VERSION MATCHES "^191[0-9]$")
    set(libbeauty_RUNTIME vc15)
  else()
    message(WARNING "libbeauty does not recognize MSVC_VERSION \"${MSVC_VERSION}\". Cannot set libbeauty_RUNTIME")
  endif()
elseif(MINGW)
  set(libbeauty_RUNTIME mingw)

  if(MINGW64)
    set(libbeauty_ARCH x64)
  else()
    set(libbeauty_ARCH x86)
  endif()
endif()

# Fix handling of duplicated files in the same static library:
# https://public.kitware.com/Bug/view.php?id=14874
if(CMAKE_VERSION VERSION_LESS "3.1")
  foreach(var CMAKE_C_ARCHIVE_APPEND CMAKE_CXX_ARCHIVE_APPEND)
    if(${var} MATCHES "^<CMAKE_AR> r")
      string(REPLACE "<CMAKE_AR> r" "<CMAKE_AR> q" ${var} "${${var}}")
    endif()
  endforeach()
endif()

if(ENABLE_CXX11)
  #cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
  set(CMAKE_CXX_EXTENSIONS OFF) # use -std=c++11 instead of -std=gnu++11
  if(CMAKE_CXX11_COMPILE_FEATURES)
    set(HAVE_CXX11 ON)
  endif()
endif()
if(NOT HAVE_CXX11)
  libbeauty_check_compiler_flag(CXX "" HAVE_CXX11 "${libbeauty_SOURCE_DIR}/cmake/checks/cxx11.cpp")
  if(NOT HAVE_CXX11 AND ENABLE_CXX11)
    libbeauty_check_compiler_flag(CXX "-std=c++11" HAVE_STD_CXX11 "${libbeauty_SOURCE_DIR}/cmake/checks/cxx11.cpp")
    if(HAVE_STD_CXX11)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
      set(HAVE_CXX11 ON)
    endif()
  endif()
endif()
