include(ExternalProject)

if(CMAKE_CROSSCOMPILING)
  set(CONFIGURE_FLAGS
    --host=${CMAKE_SYSTEM_PROCESSOR}-none-eabi --build=${CMAKE_HOST_SYSTEM_PROCESSOR}-linux-gnu)
endif()

# Remove parameters to make build identical to older build
# TODO: Remove the below hack (Use CMAKE_C_FLAGS directly instead of MODIFIED_C_FLAGS)
string(REPLACE "-mfloat-abi=softfp" "" MODIFIED_C_FLAGS_TMP ${CMAKE_C_FLAGS})
string(REPLACE "-mfpu=fpv4-sp-d16" "" MODIFIED_C_FLAGS ${MODIFIED_C_FLAGS_TMP})

#-----------------------
# noise-c

set(NOISEC_CONFIGURE_FLAGS "--with-libsodium=no --with-openssl=no")
if(SANITIZE_ADDRESS)
  set(NOISEC_CFLAGS "-fsanitize=address")
endif()
if(SANITIZE_UNDEFINED)
  set(NOISEC_CFLAGS "${NOISEC_CFLAGS} -fsanitize=undefined")
endif()
set(NOISEC_CFLAGS "\
  ${NOISEC_CFLAGS} \
  ${MODIFIED_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}} \
  -fno-strict-aliasing \
")
# Hide some warnings
set(NOISEC_CFLAGS "${NOISEC_CFLAGS} -Wformat=0 -Wno-implicit-fallthrough -Wno-undef -Wno-cast-qual -Wno-switch-default -Wno-packed -Wno-pedantic -Wno-missing-prototypes -Wno-unused-parameter -Wno-redundant-decls -Wno-missing-declarations -Wno-shadow")
if(CMAKE_CROSSCOMPILING)
  set(NOISEC_LDFLAGS "--specs=nosys.specs")
endif()
set(NOISEC_LDFLAGS "${NOISEC_LDFLAGS} ${CMAKE_C_LINK_FLAGS} -lc")

ExternalProject_Add(noise-c
  PREFIX          ${CMAKE_CURRENT_BINARY_DIR}/noise-c
  STEP_TARGETS    build-noise-c
  SOURCE_DIR      ${CMAKE_CURRENT_SOURCE_DIR}/noise-c
  CONFIGURE_COMMAND autoreconf --install --force ${CMAKE_CURRENT_SOURCE_DIR}/noise-c
  COMMAND ${CMAKE_COMMAND} -E env env
  COMMAND         ${CMAKE_COMMAND} -E env
                  "CFLAGS=${NOISEC_CFLAGS}"
                  "LDFLAGS=${NOISEC_LDFLAGS}"
                  ${CMAKE_CURRENT_SOURCE_DIR}/noise-c/configure
                  ${CONFIGURE_FLAGS}
                  ${NOISEC_CONFIGURE_FLAGS}
  BUILD_COMMAND   ${CMAKE_MAKE_PROGRAM} -C src/protocol
  INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
  COMMAND         ${CMAKE_COMMAND} -E copy
                  ${CMAKE_CURRENT_BINARY_DIR}/noise-c/src/noise-c-build/src/protocol/libnoiseprotocol.a
                  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libnoiseprotocol.a
)

add_library(noiseprotocol STATIC IMPORTED GLOBAL)
set_property(TARGET noiseprotocol
  PROPERTY IMPORTED_LOCATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/libnoiseprotocol.a)
set_target_properties(noiseprotocol
  PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES
      ${CMAKE_CURRENT_SOURCE_DIR}/noise-c/include
)
# INTERFACE_SYSTEM_INCLUDE_DIRECTORIES only modifies existing directories. WTF CMake...
set_target_properties(noiseprotocol
  PROPERTIES
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
      ${CMAKE_CURRENT_SOURCE_DIR}/noise-c/include
)
set_property(
  TARGET noiseprotocol APPEND
  PROPERTY INTERFACE_INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/noise-c/src
)
set_property(
  TARGET noiseprotocol APPEND
  PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/noise-c/src
)

#----------------------
# wally-core

# configure flags for secp256k1 bundled in libwally core, to reduce memory consumption
set(LIBWALLY_SECP256k1_FLAGS --with-ecmult-window=2 --with-ecmult-gen-precision=2 --enable-ecmult-static-precomputation)
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
  -Wno-array-bounds \
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

add_library(tinycbor STATIC
	tinycbor/src/cborerrorstrings.c
	tinycbor/src/cborencoder.c
	tinycbor/src/cborencoder_close_container_checked.c
	tinycbor/src/cborparser.c
	tinycbor/src/cborpretty.c
)
set_target_properties(tinycbor PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/tinycbor/src)
set_target_properties(tinycbor PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/tinycbor/src)

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
    cryptoauthlib/lib/atca_execution.c
    cryptoauthlib/lib/atca_iface.c
    cryptoauthlib/lib/hal/atca_hal.c
    cryptoauthlib/lib/hal/hal_timer_start.c
    cryptoauthlib/lib/basic/atca_basic.c
    cryptoauthlib/lib/basic/atca_basic_counter.c
    cryptoauthlib/lib/basic/atca_basic_gendig.c
    cryptoauthlib/lib/basic/atca_basic_nonce.c
    cryptoauthlib/lib/basic/atca_basic_checkmac.c
    cryptoauthlib/lib/basic/atca_basic_info.c
    cryptoauthlib/lib/basic/atca_basic_derivekey.c
    cryptoauthlib/lib/basic/atca_basic_random.c
    cryptoauthlib/lib/basic/atca_basic_selftest.c
    cryptoauthlib/lib/basic/atca_basic_read.c
    cryptoauthlib/lib/basic/atca_basic_privwrite.c
    cryptoauthlib/lib/basic/atca_basic_verify.c
    cryptoauthlib/lib/basic/atca_basic_write.c
    cryptoauthlib/lib/basic/atca_basic_updateextra.c
    cryptoauthlib/lib/basic/atca_basic_lock.c
    cryptoauthlib/lib/basic/atca_basic_kdf.c
    cryptoauthlib/lib/basic/atca_basic_genkey.c
    cryptoauthlib/lib/basic/atca_basic_sign.c
    cryptoauthlib/lib/host/atca_host.c
    cryptoauthlib/lib/crypto/hashes/sha2_routines.c
    cryptoauthlib/lib/crypto/atca_crypto_sw_sha2.c
  )
  target_link_libraries(cryptoauthlib samd51a-ds asf4-drivers-min)
  set_property(TARGET cryptoauthlib PROPERTY INTERFACE_LINK_LIBRARIES "")
  target_compile_definitions(cryptoauthlib PUBLIC ATCA_HAL_CUSTOM ATCA_NO_POLL)
  target_include_directories(cryptoauthlib SYSTEM PUBLIC cryptoauthlib/lib)
  target_compile_options(cryptoauthlib PRIVATE -Wno-pedantic -Wno-incompatible-pointer-types -Wno-unused-parameter -Wno-unused-variable)

  add_library(fatfs
    FatFs/source/ff.c
    FatFs/source/ffunicode.c
  )
  target_link_libraries(fatfs samd51a-ds asf4-drivers asf4-drivers-min)
  set_property(TARGET fatfs PROPERTY INTERFACE_LINK_LIBRARIES "")
  target_include_directories(fatfs SYSTEM PUBLIC FatFs/source)
  target_compile_options(fatfs PRIVATE -Wno-switch-default)
endif() # CMAKE_CROSSCOMPILING

add_library(base32
  base32/base32.c
)
target_include_directories(base32 SYSTEM PUBLIC base32)

add_library(ctaes
  ctaes/ctaes.c
  ctaes/ctaes-cbc.c
)
target_include_directories(ctaes SYSTEM PUBLIC ctaes)

add_library(sha3
  sha3/sha3.c
)
target_include_directories(sha3 SYSTEM PUBLIC sha3)
target_compile_definitions(sha3 PUBLIC USE_KECCAK)
target_compile_options(sha3 PRIVATE -Wno-cast-qual)

add_library(bignum
  bignum/bignum.c
  bignum/largeprime.c
)
target_include_directories(bignum SYSTEM PUBLIC bignum)
target_compile_options(bignum PRIVATE -Wno-missing-prototypes -Wno-missing-declarations -Wno-switch-default)
