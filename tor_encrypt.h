//
// Created by botanic on 2/6/16.
//

#ifndef LIBMJOLLNIR_TOR_ENCRYPT_H
#define LIBMJOLLNIR_TOR_ENCRYPT_H

#include "libmjollnir_int.h"

// encrypt for everyone, decrypt only my own (?)
int tor_hybrid_encrypt(gnutls_pubkey_t pubkey_in, const byte *blob_in, size_t blob_in_sz, byte **blob_out, size_t *blob_out_sz);
int tor_hybrid_decrypt(ptor_context ctx, const byte *blob_in, size_t blob_in_sz, byte **blob_out, size_t *blob_out_sz);

#endif //LIBMJOLLNIR_TOR_ENCRYPT_H
