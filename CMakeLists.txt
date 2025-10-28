cmake_minimum_required(VERSION 3.25)
project("vdeplug_agno"
    DESCRIPTION "libvdeplug plugin module for agno"
    HOMEPAGE_URL "https://github.com/rd235/vdeplug_agno"
    VERSION 0.1.2
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

set(CMAKE_REQUIRED_QUIET TRUE)
set(LIBS_REQUIRED vdeplug_mod wolfssl)
set(HEADERS_REQUIRED strcase.h libvdeplug.h strcase.h wolfssl/options.h wolfssl/wolfcrypt/aes.h wolfssl/wolfcrypt/random.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(vdeplug_agno SHARED libvdeplug_agno.c)
target_link_libraries(vdeplug_agno vdeplug_mod wolfssl)

install(TARGETS vdeplug_agno DESTINATION ${CMAKE_INSTALL_LIBDIR}/vdeplug)

add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")

