//
// Created by botanic on 1/4/16.
//

#ifndef LIBMJOLLNIR_LIBMJOLLNIR_INT_H
#define LIBMJOLLNIR_LIBMJOLLNIR_INT_H
/*
 * stuff, hidden from a man`s eye
 * */
#include "libmjollnir.h"
#include <gnutls/gnutls.h>

// use GNUTLS_E_* codes for errors - for now

struct _tor_context {

    gnutls_pubkey_t pubkey;
};

struct _tor_socket {

};

#endif //LIBMJOLLNIR_LIBMJOLLNIR_INT_H
