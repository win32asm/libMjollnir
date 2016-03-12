//
// Created by botanic on 1/7/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include "tor_keys.h"
#include "tor_params.h"

int
tor_load_context(ptor_context *ctxt, const char *fname)
{
    FILE *f=fopen(fname, "r");

    if (f == NULL) {
        return GNUTLS_E_FILE_ERROR;
    }
    // todo: read cert data
    fclose(f);

    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

int
tor_init_context(ptor_context *pctx)
{
    ptor_context ctx;
    int error;

    ctx = (ptor_context)malloc(sizeof(struct _tor_context));
    if (ctx == NULL) {
        *pctx = NULL;
        return GNUTLS_E_MEMORY_ERROR;
    }

    memset(ctx, 0, sizeof(ptor_context));

    if (GNUTLS_E_SUCCESS != (error=gnutls_privkey_init(&ctx->masterkey))) goto failed;
    if (GNUTLS_E_SUCCESS != (error=gnutls_privkey_init(&ctx->privkey)))   goto failed;
    if (GNUTLS_E_SUCCESS != (error=gnutls_pubkey_init(&ctx->pubkey)))     goto failed;
    if (GNUTLS_E_SUCCESS != (error=gnutls_privkey_generate(ctx->masterkey, GNUTLS_PK_RSA, RSA_KEYLEN, 0))) goto failed;
    if (GNUTLS_E_SUCCESS != (error=gnutls_privkey_generate(ctx->privkey, GNUTLS_PK_RSA, RSA_KEYLEN, 0 )))  goto failed;
    if (GNUTLS_E_SUCCESS != (error=gnutls_pubkey_import_privkey(ctx->pubkey, ctx->privkey, GNUTLS_KEY_DECIPHER_ONLY, 0))) goto failed;

    // todo: generate elliptic keys

    *pctx = ctx;
    return GNUTLS_E_SUCCESS;

failed:
    tor_free_context(ctx);
    *pctx = NULL;
    return error;
}

int
tor_save_context(struct _tor_context *ctxt, const char *fname)
{
    // todo: save key data
    return GNUTLS_E_UNIMPLEMENTED_FEATURE;
}

void
tor_free_context(struct _tor_context* ctxt)
{
    assert(ctxt != NULL);
    gnutls_privkey_deinit(ctxt->masterkey);
    gnutls_privkey_deinit(ctxt->privkey);
    gnutls_pubkey_deinit(ctxt->pubkey);
    free (ctxt);
}