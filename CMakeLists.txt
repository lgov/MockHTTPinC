cmake_minimum_required (VERSION 2.6)
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

# create a shared library
add_library(mockhttp SHARED MockHTTP.c MockHTTP_server.c)
target_link_libraries(mockhttp ${LIBS})

# create target 'check', build the test suite executable and run it.
add_custom_target(check COMMAND tests/mockhttp_tests)
add_executable(tests/mockhttp_tests EXCLUDE_FROM_ALL tests/expectations.c 
               tests/httpClient.c tests/CuTest/CuTest.c MockHTTP.c 
               MockHTTP_server.c)
target_link_libraries(tests/mockhttp_tests ${LIBS})
