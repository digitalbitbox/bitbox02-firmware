include(ExternalProject)

if(CMAKE_CROSSCOMPILING)
  set(CONFIGURE_FLAGS
    --host=${CMAKE_SYSTEM_PROCESSOR}-none-eabi
    --build=${CMAKE_HOST_SYSTEM_PROCESSOR}-linux-gnu
    "$<$<BOOL:${CMAKE_C_COMPILER_LAUNCHER}>:CC=${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER}>"
  )
endif()

# Remove parameters to make build identical to older build
# TODO: Remove the below hack (Use CMAKE_C_FLAGS directly instead of MODIFIED_C_FLAGS)
string(REPLACE "-mfloat-abi=softfp" "" MODIFIED_C_FLAGS_TMP ${CMAKE_C_FLAGS})
string(REPLACE "-mfpu=fpv4-sp-d16" "" MODIFIED_C_FLAGS ${MODIFIED_C_FLAGS_TMP})

#----------------------
# wally-core

# configure flags for secp256k1 bundled in libwally core, to reduce memory consumption
set(LIBWALLY_SECP256k1_FLAGS --with-ecmult-window=2 --with-ecmult-gen-precision=2 --enable-ecmult-static-precomputation --enable-module-schnorrsig)
set(LIBWALLY_CONFIGURE_FLAGS --enable-static --disable-shared --disable-tests ${LIBWALLY_SECP256k1_FLAGS})
if(SANITIZE_ADDRESS)
  set(LIBWALLY_CFLAGS "-fsanitize=address")
endif()
if(SANITIZE_UNDEFINED)
  set(LIBWALLY_CFLAGS "${LIBWALLY_CFLAGS} -fsanitize=undefined")
endif()
# USE_BASIC_CONFIG is for secp256k1
# _DEFAULT_SOURCE enables the BSD explicit_bzero function referenced by libwally.
set(LIBWALLY_CFLAGS  "\
  ${LIBWALLY_CFLAGS} \
  ${MODIFIED_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}} \
  -DUSE_BASIC_CONFIG=1 \
  -D_DEFAULT_SOURCE \
  -fno-strict-aliasing \
")

# Hide some warnings
set(LIBWALLY_CFLAGS "${LIBWALLY_CFLAGS} -Wno-cast-qual -Wno-cast-align \
  -Wno-missing-prototypes -Wno-redundant-decls \
  -Wno-switch-default -Wno-missing-declarations \
  -Wno-array-bounds -Wno-unused-label -Wno-sign-compare -Wno-type-limits \
")
if(CMAKE_CROSSCOMPILING)
  set(LIBWALLY_LDFLAGS --specs=nosys.specs)
endif()
set(LIBWALLY_LDFLAGS "${LIBWALLY_LDFLAGS} ${CMAKE_C_LINK_FLAGS}")

ExternalProject_Add(libwally-core
  PREFIX          ${CMAKE_CURRENT_BINARY_DIR}/libwally-core
  STEP_TARGETS   build-libwally
  SOURCE_DIR      ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core
  CONFIGURE_COMMAND autoreconf --install --force ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core
  COMMAND         ${CMAKE_COMMAND} -E env
                  "CFLAGS=${LIBWALLY_CFLAGS}"
                  "LDFLAGS=${LIBWALLY_LDFLAGS}"
                  ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core/configure
                  ${CONFIGURE_FLAGS}
                  ${LIBWALLY_CONFIGURE_FLAGS}
  # TODO: Add darwin hack to libwally repo
  BUILD_COMMAND   ${CMAKE_MAKE_PROGRAM}
  INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
  COMMAND         ${CMAKE_COMMAND} -E copy
                  ${CMAKE_CURRENT_BINARY_DIR}/libwally-core/src/libwally-core-build/src/.libs/libwallycore.a
                  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libwallycore.a
  COMMAND         ${CMAKE_COMMAND} -E copy
                  ${CMAKE_CURRENT_BINARY_DIR}/libwally-core/src/libwally-core-build/src/secp256k1/.libs/libsecp256k1.a
                  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libsecp256k1.a
)

add_library(wallycore STATIC IMPORTED GLOBAL)
set_property(TARGET wallycore
  PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libwallycore.a)
set_target_properties(wallycore PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core/include)
set_target_properties(wallycore PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core/include)

add_library(secp256k1 STATIC IMPORTED GLOBAL)
set_property(TARGET secp256k1
  PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libsecp256k1.a)
set_target_properties(secp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core/src/secp256k1/include)
set_target_properties(secp256k1 PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libwally-core/src/secp256k1/include)

set(MBEDTLS_CFLAGS "-mcpu=cortex-m4 -mthumb -mlong-calls -mfloat-abi=softfp -mfpu=fpv4-sp-d16 -fomit-frame-pointer -D__SAMD51J20A__")

#set(ENABLE_TESTING OFF CACHE BOOL "Turn off testing in mbedtls" FORCE)
#add_subdirectory(mbedtls)
ExternalProject_Add(mbedtls-project
  PREFIX            ${CMAKE_CURRENT_BINARY_DIR}/mbedtls
  SOURCE_DIR        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off -DCMAKE_TOOLCHAIN_FILE=../../arm.cmake -DCMAKE_C_FLAGS=${MBEDTLS_CFLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls
  INSTALL_COMMAND   ${CMAKE_COMMAND} -E make_directory ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
  COMMAND           ${CMAKE_COMMAND} -E copy
                      ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/src/mbedtls-project-build/library/libmbedtls.a
                      ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libmbedtls.a
  COMMAND           ${CMAKE_COMMAND} -E copy
                      ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/src/mbedtls-project-build/library/libmbedx509.a
                      ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libmbedx509.a
  COMMAND           ${CMAKE_COMMAND} -E copy
                      ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/src/mbedtls-project-build/library/libmbedcrypto.a
                      ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libmbedcrypto.a
)

add_library(mbedtls STATIC IMPORTED GLOBAL)
set_property(TARGET mbedtls
  PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libmbedtls.a)
set_target_properties(mbedtls PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)

add_library(mbedx509 STATIC IMPORTED GLOBAL)
set_property(TARGET mbedx509
  PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libmbedx509.a)
set_target_properties(mbedx509 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)

add_library(mbedcrypto STATIC IMPORTED GLOBAL)
set_property(TARGET mbedcrypto
  PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libmbedcrypto.a)
set_target_properties(mbedcrypto PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)


if(CMAKE_CROSSCOMPILING)
  # Cortex Microcontroller Software Interface Standard
  add_library(CMSIS INTERFACE)
  target_include_directories(CMSIS SYSTEM INTERFACE CMSIS/Include)

  # Atmel SAMD51 Series Device Support
  add_library(samd51a-ds STATIC
    samd51a-ds/gcc/system_samd51.c
    samd51a-ds/gcc/gcc/startup_samd51.c
  )
  target_include_directories(samd51a-ds SYSTEM
    PUBLIC
      samd51a-ds/include
  )
  target_link_libraries(samd51a-ds
    PUBLIC
      CMSIS
  )

  # Advanced Software Framework Drivers
  # Only drivers needed for bootloader (minimal set)
  add_library(asf4-drivers-min STATIC
    asf4-drivers/hal/utils/src/utils_syscalls.c
    asf4-drivers/hal/utils/src/utils_list.c
    asf4-drivers/hal/src/hal_atomic.c
    asf4-drivers/hal/src/hal_gpio.c
    asf4-drivers/hal/src/hal_init.c
    asf4-drivers/hal/src/hal_delay.c
    asf4-drivers/hal/src/hal_timer.c
    asf4-drivers/hal/src/hal_usb_device.c
    asf4-drivers/hal/src/hal_rand_sync.c
    asf4-drivers/hal/src/hal_flash.c
    asf4-drivers/hal/src/hal_pac.c
    asf4-drivers/hal/src/hal_io.c
    asf4-drivers/hal/src/hal_sha_sync.c
    asf4-drivers/hpl/systick/hpl_systick.c
    asf4-drivers/hal/src/hal_usart_async.c
    asf4-drivers/hal/utils/src/utils_ringbuffer.c
    asf4-drivers/hpl/gclk/hpl_gclk.c
    asf4-drivers/hpl/oscctrl/hpl_oscctrl.c
    asf4-drivers/hpl/mclk/hpl_mclk.c
    asf4-drivers/hpl/osc32kctrl/hpl_osc32kctrl.c
    asf4-drivers/hpl/core/hpl_init.c
    asf4-drivers/hpl/core/hpl_core_m4.c
    asf4-drivers/hpl/spi/spi_lite.c
    asf4-drivers/hpl/usb/hpl_usb.c
    asf4-drivers/hpl/rtc/hpl_rtc.c
    asf4-drivers/hpl/sercom/hpl_sercom.c
    asf4-drivers/hpl/trng/hpl_trng.c
    asf4-drivers/hpl/nvmctrl/hpl_nvmctrl.c
    asf4-drivers/hpl/icm/hpl_icm.c
    asf4-drivers/hpl/pac/hpl_pac.c
    asf4-drivers/usb/usb_protocol.c
    asf4-drivers/usb/device/usbdc.c
    )

  target_link_libraries(asf4-drivers-min samd51a-ds)
  set_property(TARGET asf4-drivers-min PROPERTY INTERFACE_LINK_LIBRARIES "")

  target_include_directories(asf4-drivers-min SYSTEM
    PUBLIC
      asf4-drivers
      asf4-drivers/Config
      asf4-drivers/hal/include
      asf4-drivers/hal/include
      asf4-drivers/hal/utils/include
      asf4-drivers/hpl/core
      asf4-drivers/hpl/gclk
      asf4-drivers/hpl/pm
      asf4-drivers/hpl/port
      asf4-drivers/hpl/pukcc
      asf4-drivers/hpl/rtc
      asf4-drivers/hpl/spi
      asf4-drivers/hri
      asf4-drivers/qtouch
      asf4-drivers/qtouch/include
      asf4-drivers/sd_mmc
      asf4-drivers/usb
      asf4-drivers/usb/class
      asf4-drivers/usb/class/hid
      asf4-drivers/usb/device
  )

  # Advanced Software Framework Drivers
  # All drivers
  add_library(asf4-drivers STATIC
    asf4-drivers/hal/src/hal_mci_sync.c
    asf4-drivers/hal/src/hal_i2c_m_sync.c
    asf4-drivers/hpl/sdhc/hpl_sdhc.c
    asf4-drivers/hpl/sercom/hpl_sercom.c
    asf4-drivers/sd_mmc/sd_mmc.c
    asf4-drivers/diskio/sdmmc_diskio.c
  )
  target_link_libraries(asf4-drivers
    PRIVATE
      samd51a-ds
    PUBLIC
      asf4-drivers-min
  )

  target_include_directories(asf4-drivers SYSTEM
    PUBLIC
      asf4-drivers/diskio
  )
set_property(TARGET asf4-drivers PROPERTY INTERFACE_LINK_LIBRARIES "")

  find_library(QTOUCHLIB_A qtm_acq_samd51_0x000f PATHS asf4-drivers/qtouch/lib/gcc NO_CMAKE_FIND_ROOT_PATH)
  find_library(QTOUCHLIB_B qtm_binding_layer_cm4_0x0005 PATHS asf4-drivers/qtouch/lib/gcc NO_CMAKE_FIND_ROOT_PATH)
  find_library(QTOUCHLIB_T qtm_touch_key_cm4_0x0002 PATHS asf4-drivers/qtouch/lib/gcc NO_CMAKE_FIND_ROOT_PATH)

  add_library(cryptoauthlib
    cryptoauthlib/lib/atca_cfgs.c
    cryptoauthlib/lib/atca_command.c
    cryptoauthlib/lib/atca_device.c
    cryptoauthlib/lib/atca_iface.c
    cryptoauthlib/lib/hal/atca_hal.c
    cryptoauthlib/lib/hal/hal_timer_start.c
    cryptoauthlib/lib/atca_basic.c
    cryptoauthlib/lib/atca_debug.c
    cryptoauthlib/lib/calib/calib_basic.c
    cryptoauthlib/lib/calib/calib_command.c
    cryptoauthlib/lib/calib/calib_execution.c
    cryptoauthlib/lib/calib/calib_counter.c
    cryptoauthlib/lib/calib/calib_gendig.c
    cryptoauthlib/lib/calib/calib_nonce.c
    cryptoauthlib/lib/calib/calib_checkmac.c
    cryptoauthlib/lib/calib/calib_info.c
    cryptoauthlib/lib/calib/calib_derivekey.c
    cryptoauthlib/lib/calib/calib_random.c
    cryptoauthlib/lib/calib/calib_selftest.c
    cryptoauthlib/lib/calib/calib_read.c
    cryptoauthlib/lib/calib/calib_privwrite.c
    cryptoauthlib/lib/calib/calib_verify.c
    cryptoauthlib/lib/calib/calib_write.c
    cryptoauthlib/lib/calib/calib_updateextra.c
    cryptoauthlib/lib/calib/calib_lock.c
    cryptoauthlib/lib/calib/calib_kdf.c
    cryptoauthlib/lib/calib/calib_genkey.c
    cryptoauthlib/lib/calib/calib_sign.c
    cryptoauthlib/lib/host/atca_host.c
    cryptoauthlib/lib/crypto/hashes/sha2_routines.c
    cryptoauthlib/lib/crypto/atca_crypto_sw_sha2.c
  )
  target_link_libraries(cryptoauthlib samd51a-ds asf4-drivers-min)
  set_property(TARGET cryptoauthlib PROPERTY INTERFACE_LINK_LIBRARIES "")
  target_include_directories(cryptoauthlib SYSTEM PUBLIC
    cryptoauthlib/lib
    ${CMAKE_CURRENT_SOURCE_DIR} # for the BitBox02-custom "atca_config.h"
    )
  target_compile_options(cryptoauthlib PRIVATE
    -Wno-pedantic -Wno-incompatible-pointer-types -Wno-unused-parameter -Wno-unused-variable -Wno-cast-qual
    -Wno-switch-default -Wno-format-nonliteral -Wno-missing-prototypes -Wno-missing-declarations
  )
endif() # CMAKE_CROSSCOMPILING

# fatfs must to be linked together with a diskio middleware:
# - in the firmware, it is linked with asf4-drivers, which contains sdmmc_diskio.c (writing to actual microSD cards)
# - in unit tests, it is linked with a lib containing mock_diskio.c (volume mounted in RAM).
add_library(fatfs
  fatfs/source/ff.c
  fatfs/source/ffunicode.c
  )
set_property(TARGET fatfs PROPERTY INTERFACE_LINK_LIBRARIES "")
target_include_directories(fatfs SYSTEM PUBLIC fatfs/source)
target_compile_options(fatfs PRIVATE -Wno-switch-default)

add_library(ctaes
  ctaes/ctaes.c
)
target_include_directories(ctaes SYSTEM PUBLIC ctaes)

# optiga-trust-m

add_library(optiga
  optiga-trust-m/optiga/cmd/optiga_cmd.c
  optiga-trust-m/optiga/common/optiga_lib_common.c
  optiga-trust-m/optiga/common/optiga_lib_logger.c
  optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c.c
  optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_config.c
  optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
  optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
  optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_presentation_layer.c
  optiga-trust-m/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
  optiga-trust-m/optiga/comms/optiga_comms_ifx_i2c.c
  optiga-trust-m/optiga/crypt/optiga_crypt.c
  optiga-trust-m/optiga/util/optiga_util.c
)
target_include_directories(optiga SYSTEM PUBLIC optiga-trust-m/optiga/include)
