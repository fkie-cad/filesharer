set(APP FShare)

add_executable(${APP}
    ""
    )
target_sources(${APP} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fshare.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/FsHeader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/collections/Fifo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/crypto/linux/HasherOpenSSL.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/crypto/linux/AESOpenSSL.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/crypto/linux/RSAOpenSSL.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/crypto/linux/crypto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/files/Files.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/files/FilesL.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/net/linSock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/net/sock.c
)
if (DEBUG_PRINT)
    target_sources(${APP} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/debug.c
        )
endif()

target_link_libraries(${APP} PRIVATE OpenSSL::Crypto)
