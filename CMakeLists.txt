cmake_minimum_required(VERSION 3.1)
project("vdeplug_agno"
    DESCRIPTION "libvdeplug plugin module for agno"
    HOMEPAGE_URL "https://github.com/rd235/vdeplug_agno"
    VERSION 0.1.0
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)

set(CMAKE_REQUIRED_QUIET TRUE)
set(LIBS_REQUIRED vdeplug_mod ssl crypto)
set(HEADERS_REQUIRED libvdeplug.h openssl/aes.h openssl/rand.h)

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
target_link_libraries(vdeplug_agno vdeplug_mod ssl crypto)

install(TARGETS vdeplug_agno DESTINATION ${CMAKE_INSTALL_LIBDIR}/vdeplug)

add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")

