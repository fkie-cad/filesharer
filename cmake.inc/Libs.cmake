enable_testing()
find_package(GTest QUIET)
#include_directories(${GTEST_INCLUDE_DIRS})
message("-- GTEST_FOUND: ${GTEST_FOUND} ${GTEST_BOTH_LIBRARIES}")

# open ssl
#include_directories(/usr/include/openssl/)
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message("OpenSSL " OpenSSL)
    set(OPENSSL_USE_SHARED_LIBS TRUE)
endif()

set(LIB_EXTENSION so)
