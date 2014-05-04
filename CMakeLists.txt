cmake_minimum_required (VERSION 2.8.8)
project (MockHTTPinC)

# include OpenSSL (optional)
find_package (OpenSSL)
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})
set(CMAKE_C_FLAGS -DMOCKHTTP_OPENSSL)
IF (OPENSSL_LIBRARIES)
    MESSAGE(STATUS "Found OPENSSL: ${OPENSSL_LIBRARIES}")
ENDIF (OPENSSL_LIBRARIES)

# include APR (required) and APR-UTIL (required)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package (APR)
set(LIBS ${LIBS} ${APR_LIBRARIES} ${APRUTIL_LIBRARIES})

include_directories(${APR_INCLUDE_DIR})
include_directories(${APRUTIL_INCLUDE_DIR})

include_directories(.)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

# create a static and a shared library
set(MH_VERSION_MAJOR 0)
set(MH_VERSION_MINOR 1)
set(MH_VERSION_PATCH 0)
set(MH_VERSION_STRING ${MH_VERSION_MAJOR}.${MH_VERSION_MINOR}.${MH_VERSION_PATCH})

set(SOURCES MockHTTP.c MockHTTP_server.c)
add_library (objects OBJECT ${SOURCES})
add_library (mockhttp_static STATIC $<TARGET_OBJECTS:objects>)
add_library (mockhttp_shared SHARED $<TARGET_OBJECTS:objects>)

set_target_properties(mockhttp_shared PROPERTIES VERSION ${MH_VERSION_STRING}
                                                 SOVERSION ${MH_VERSION_MAJOR}
                                                 OUTPUT_NAME mockhttp)
target_link_libraries(mockhttp_shared ${LIBS})
# give both static and shared libraries the same name (.so/.dylib vs .a), except
# on Windows where both have extension .lib
if (NOT WIN32)
  set_target_properties(mockhttp_static PROPERTIES OUTPUT_NAME mockhttp)
endif (NOT WIN32)

# create target 'check', build the test suite executable and run it.
add_custom_target(check COMMAND tests/mockhttp_tests)
add_executable(tests/mockhttp_tests EXCLUDE_FROM_ALL tests/expectations.c 
               tests/httpClient.c tests/CuTest/CuTest.c MockHTTP.c 
               MockHTTP_server.c)
target_link_libraries(tests/mockhttp_tests ${LIBS})
