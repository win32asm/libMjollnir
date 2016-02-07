cmake_minimum_required(VERSION 3.3)
project(libMjollnir)

include_directories(
        /usr/include
)

find_library(gnutls NAMES libgnutls-deb0 libgnutls)
find_library(nettle NAMES libnettle libnettle4)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -lnettle -lgnutls")

set(SOURCE_FILES main.c libmjollnir.h libmjollnir_int.h tor_setup.c tor_params.h tor_params.c
        # gnutls library - for CLion
        /usr/include/gnutls/abstract.h
        /usr/include/gnutls/compat.h
        /usr/include/gnutls/crypto.h
        /usr/include/gnutls/dtls.h
        /usr/include/gnutls/gnutls.h
        /usr/include/gnutls/ocsp.h
        /usr/include/gnutls/openpgp.h
        /usr/include/gnutls/openssl.h
        /usr/include/gnutls/pkcs11.h
        /usr/include/gnutls/pkcs12.h
        /usr/include/gnutls/self-test.h
        /usr/include/gnutls/tpm.h
        /usr/include/gnutls/x509-ext.h
        /usr/include/gnutls/x509.h
        # nettle library - for CLion
        /usr/include/nettle/aes.h
        /usr/include/nettle/ctr.h
        /usr/include/nettle/nettle-types.h


        tor_keys.c tor_keys.h tor_encrypt.c tor_encrypt.h)
add_executable(libMjollnir ${SOURCE_FILES})