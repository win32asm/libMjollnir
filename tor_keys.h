//
// Created by botanic on 1/7/16.
//

#ifndef LIBMJOLLNIR_TOR_KEYS_H
#define LIBMJOLLNIR_TOR_KEYS_H

// Every Tor relay has multiple public/private keypairs:

#include "libmjollnir_int.h"

int tor_load_context(ptor_context *ctxt, const char *fname);
int tor_init_context(ptor_context *ctxt);
void tor_free_context(ptor_context ctxt);
int  tor_save_context(ptor_context ctxt, const char *fname);


#endif //LIBMJOLLNIR_TOR_KEYS_H
