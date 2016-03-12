//
// Created by botanic on 2/6/16.
//

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "tor_params.h"
#include "tor_encrypt.h"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <gnutls/gnutls.h>

/**
   The "hybrid encryption" of a byte sequence M with a public key PK is
   computed as follows:
      1. If M is less than PK_ENC_LEN-PK_PAD_LEN, pad and encrypt M with PK.
      2. Otherwise, generate a KEY_LEN byte random key K.
         Let M1 = the first PK_ENC_LEN-PK_PAD_LEN-KEY_LEN bytes of M,
         and let M2 = the rest of M.
         Pad and encrypt K|M1 with PK.  Encrypt M2 with our stream cipher,
         using the key K.  Concatenate these encrypted values.
 **/
int tor_hybrid_encrypt(gnutls_pubkey_t pubkey_in, const byte *blob_in, size_t blob_in_sz, byte **blob_out, size_t *blob_out_sz) {
    int rslt;
    assert(blob_in  != NULL);
    assert(blob_out != NULL);
    assert(blob_out_sz != NULL);
    assert(pubkey_in != NULL);

    if (blob_in_sz < (PK_ENC_LEN-PK_PAD_LEN)) {
        byte * outbuf = (byte*)malloc(PK_ENC_LEN);

        if (outbuf == NULL) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        {   // do pubkey encrypt
            gnutls_datum_t inp = {.data = (unsigned char *) blob_in, .size = (unsigned int) blob_in_sz};
            gnutls_datum_t out;

            rslt = gnutls_pubkey_encrypt_data(pubkey_in, 0, &inp, &out);
            if (rslt != GNUTLS_E_SUCCESS) {
                free(outbuf);  // VB: encrypt failed, don`t need to clean?
                return rslt;
            }
            assert(out.size == PK_ENC_LEN);
            memcpy(outbuf, out.data, PK_ENC_LEN);
            gnutls_free(out.data);
            *blob_out_sz = PK_ENC_LEN;
            *blob_out = outbuf;
        }
    } else {
        byte *inbuf =  (byte*)malloc(PK_ENC_LEN-PK_PAD_LEN);
        byte *outbuf = (byte*)malloc(blob_in_sz + KEY_LEN+PK_PAD_LEN); // [KEY|M1|padding]<M2>

        if (outbuf == NULL || inbuf == NULL) {
            return GNUTLS_E_MEMORY_ERROR;
        }

        gnutls_rnd(GNUTLS_RND_RANDOM, inbuf, KEY_LEN);

        {   // do AES crypt
            struct aes_ctx localCtx;
            byte ctrData[KEY_LEN];
            nettle_aes_set_encrypt_key(&localCtx, KEY_LEN, inbuf);
            memset(ctrData, 0, KEY_LEN); // iv=0

            nettle_ctr_crypt(&localCtx, (void (*)(void *, unsigned int, uint8_t *, const uint8_t *)) nettle_aes_encrypt,
                             KEY_LEN, ctrData, (unsigned int) (blob_in_sz - (PK_ENC_LEN - PK_PAD_LEN - KEY_LEN)),
                             outbuf+PK_ENC_LEN, blob_in + (PK_ENC_LEN-PK_PAD_LEN) - KEY_LEN);
        }

        // construct [key|M1] part
        memcpy(inbuf+KEY_LEN,blob_in, PK_ENC_LEN-PK_PAD_LEN-KEY_LEN);
        {   // do pubkey encrypt
            gnutls_datum_t inp = {.data = inbuf, .size = PK_ENC_LEN-PK_PAD_LEN};
            gnutls_datum_t out;

            rslt = gnutls_pubkey_encrypt_data(pubkey_in, 0, &inp, &out);
            if (rslt != GNUTLS_E_SUCCESS) {
                memset(inbuf, 0, PK_ENC_LEN-PK_PAD_LEN);
                free(inbuf);
                free(outbuf);  // VB: encrypt failed, don`t need to clean?
                return rslt;
            }
            assert(out.size == PK_ENC_LEN);
            memcpy(outbuf, out.data, PK_ENC_LEN);
            gnutls_free(out.data);
            *blob_out_sz = PK_ENC_LEN;
            *blob_out = outbuf;
        }
    }

    return GNUTLS_E_SUCCESS;
}

int tor_hybrid_decrypt(ptor_context ctx, const byte *blob_in, size_t blob_in_sz, byte **blob_out, size_t *blob_out_sz) {
    int rslt;
    assert(blob_in  != NULL);
    assert(blob_out != NULL);
    assert(blob_out_sz != NULL);
    assert(blob_in_sz >= PK_ENC_LEN);
    assert(ctx != NULL);

    byte * outbuf = (byte*)malloc(blob_in_sz);

    if (outbuf == NULL) {
        return GNUTLS_E_MEMORY_ERROR;
    }

    {   // do privkey decrypt
        gnutls_datum_t inp = {.data = (unsigned char *) blob_in, .size = PK_ENC_LEN };
        gnutls_datum_t out;

        rslt = gnutls_privkey_decrypt_data(ctx->privkey, 0, &inp, &out);
        if (rslt != GNUTLS_E_SUCCESS) {
            free(outbuf);  // VB: encrypt failed, don`t need to clean?
            return rslt;
        }
        memcpy(outbuf, out.data, PK_ENC_LEN);
        gnutls_free(out.data);
    }

    if (blob_in_sz > (PK_ENC_LEN-PK_PAD_LEN)) {   // do AES decrypt
        struct aes_ctx localCtx;
        byte ctrData[KEY_LEN];
        nettle_aes_set_encrypt_key(&localCtx, KEY_LEN, outbuf);
        memset(ctrData, 0, KEY_LEN); // iv=0

        nettle_ctr_crypt(&localCtx, (void (*)(void *, unsigned int, uint8_t *, const uint8_t *)) nettle_aes_decrypt,
                         KEY_LEN, ctrData, (unsigned int) (blob_in_sz - PK_ENC_LEN),
                         outbuf+PK_ENC_LEN, blob_in + PK_ENC_LEN);
    }

    *blob_out_sz = PK_ENC_LEN;
    *blob_out = outbuf;

    return GNUTLS_E_SUCCESS;
}
