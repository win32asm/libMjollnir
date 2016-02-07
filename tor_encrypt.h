//
// Created by botanic on 2/6/16.
//

#ifndef LIBMJOLLNIR_TOR_ENCRYPT_H
#define LIBMJOLLNIR_TOR_ENCRYPT_H

#include "libmjollnir_int.h"

int tor_hybrid_encrypt(ptor_context ctx, const byte *blob_in, size_t blob_in_sz, byte **blob_out, size_t *blob_out_sz);

#endif //LIBMJOLLNIR_TOR_ENCRYPT_H
