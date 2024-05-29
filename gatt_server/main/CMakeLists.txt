set(requires "")
idf_build_get_property(target IDF_TARGET)

if(${target} STREQUAL "linux")
    list(APPEND requires esp_stubs esp-tls esp_http_client protocol_examples_common nvs_flash)
endif()
idf_component_register(SRCS "gatts_demo.c" "icheer_aes.c" "icheer_aesdata.c" "md5.c"
                    INCLUDE_DIRS "."
                    REQUIRES ${requires}
                    EMBED_TXTFILES howsmyssl_com_root_cert.pem
                    postman_root_cert.pem)