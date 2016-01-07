//
// Created by botanic on 1/6/16.
// defines as per section 0.2 of https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt
//

#ifndef LIBMJOLLNIR_TOR_PARAMS_H
#define LIBMJOLLNIR_TOR_PARAMS_H
#include <gnutls/gnutls.h>

typedef unsigned char byte, *pbyte;

#define KEY_LEN (16)      // the length of the stream cipher's key, in bytes.
#define PK_ENC_LEN (128)  // the length of a public-key encrypted message, in bytes.
#define PK_PAD_LEN (42)   // the number of bytes added in padding for public-key
                          // encryption, in bytes. (The largest number of bytes that can be encrypted
                          // in a single public-key operation is therefore PK_ENC_LEN-PK_PAD_LEN.)

#define DH_LEN (128)      // the number of bytes used to represent a member of the
                          // Diffie-Hellman group.
#define DH_SEC_LEN (40)   // the number of bytes used in a Diffie-Hellman private key (x).

#define HASH_LEN (20)     // the length of the hash function's output, in bytes.

#define PAYLOAD_LEN (509) // The longest allowable cell payload, in bytes. (509)

#define CELL_LEN(v) ((v<4)?512:514) //-- The length of a Tor cell, in bytes, for link protocol version v.
                                    // CELL_LEN(v) = 512 if v is less than 4; 514 otherwise.

extern const gnutls_datum_t tor_DH_g;
extern const gnutls_datum_t tor_DH_p;

#endif //LIBMJOLLNIR_TOR_PARAMS_H
