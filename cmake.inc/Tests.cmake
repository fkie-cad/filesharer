if ( ${GTEST_FOUND} )


endif()

set(Tests Tests)

message("Tests ")
if (DEBUG_PRINT)
message("DEBUG_PRINT : ${DEBUG_PRINT}")
    endif()
add_executable(${Tests}
    ""
    )
target_sources(${Tests} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/testAESOpenSSL.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/testRSAOpenSSL.h
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/crypto/linux/AESOpenSSL.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/crypto/linux/RSAOpenSSL.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/debug.c
    )

target_link_libraries(${Tests} PRIVATE OpenSSL::Crypto)
