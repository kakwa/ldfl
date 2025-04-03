# Author: David Demelier License: ISC
# https://hg.malikania.fr/molko/file/65a07c7d8ff4/cmake/FindJansson.cmake

# FindJansson
# -----------
#
# Find Jansson library, this modules defines:
#
# JANSSON_INCLUDE_DIRS, where to find jansson.h JANSSON_LIBRARIES, where to find
# library JANSSON_FOUND, if it is found
#
# The following imported targets will be available:
#
# Jansson::Jansson, if found.
#

find_path(JANSSON_INCLUDE_DIR NAMES jansson.h)
find_library(JANSSON_LIBRARY NAMES libjansson jansson)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  Jansson
  FOUND_VAR JANSSON_FOUND
  REQUIRED_VARS JANSSON_LIBRARY JANSSON_INCLUDE_DIR)

if(JANSSON_FOUND)
  set(JANSSON_LIBRARIES ${JANSSON_LIBRARY})
  set(JANSSON_INCLUDE_DIRS ${JANSSON_INCLUDE_DIR})
  if(NOT TARGET Jansson::Jansson)
    add_library(Jansson::Jansson UNKNOWN IMPORTED)
    set_target_properties(
      Jansson::Jansson
      PROPERTIES IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                 IMPORTED_LOCATION "${JANSSON_LIBRARY}"
                 INTERFACE_INCLUDE_DIRECTORIES "${JANSSON_INCLUDE_DIRS}")
  endif()
endif()

mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARY)
