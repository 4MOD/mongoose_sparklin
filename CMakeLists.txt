idf_component_register(SRCS "mongoose/mongoose.c"
                       INCLUDE_DIRS "mongoose"
                       REQUIRES lwip mbedtls esp_timer app_update)

target_compile_definitions(${COMPONENT_LIB} PRIVATE MG_ENABLE_MBEDTLS=1)
