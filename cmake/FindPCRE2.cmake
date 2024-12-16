# Look for the PCRE library and headers

find_path(PCRE2_INCLUDE_DIR pcre2.h)
find_library(PCRE2_LIBRARY NAMES pcre2-8)

# Check if the library and headers were found

if(PCRE2_INCLUDE_DIR AND PCRE2_LIBRARY)
  set(PCRE2_FOUND TRUE)
endif()

# Report the results

if(PCRE2_FOUND)
  message(STATUS "Found PCRE2: ${PCRE2_INCLUDE_DIR}, ${PCRE2_LIBRARY}")
else()
  message(STATUS "Could not find PCRE2")
endif()

# Define the PCRE target

if(PCRE2_FOUND)
  add_library(PCRE2::PCRE2 INTERFACE IMPORTED)
  target_include_directories(PCRE2::PCRE2 INTERFACE ${PCRE2_INCLUDE_DIR})
  target_link_libraries(PCRE2::PCRE2 INTERFACE ${PCRE2_LIBRARY})
endif()
