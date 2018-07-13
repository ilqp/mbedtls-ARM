add_executable(aesgcm aesgcm.c)
target_link_libraries(aesgcm mbedaesgcm)

add_executable(aesgcm2 aesgcm2.c)
target_link_libraries(aesgcm2 mbedtls)

install(TARGETS aesgcm aesgcm2
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
