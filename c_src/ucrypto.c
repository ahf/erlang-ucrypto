/* vim: set sw=4 sts=4 et foldmethod=syntax : */

/*
 * Copyright (c) 2012 Alexander Færøy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ucrypto.h"
#include "ucrypto_ec.h"
#include "ucrypto_ripemd160.h"

static ErlNifFunc nif_functions[] = {
    /* RIPEMD160 */
    {"ripemd160_nif", 1, ucrypto_ripemd160_nif},
    {"ripemd160_init_nif", 0, ucrypto_ripemd160_init_nif},
    {"ripemd160_update_nif", 2, ucrypto_ripemd160_update_nif},
    {"ripemd160_final_nif", 1, ucrypto_ripemd160_final_nif},

    /* EC */
    {"ec_new_by_curve_nif", 1, ucrypto_ec_new_by_curve_nif},
    {"ec_generate_key_nif", 1, ucrypto_ec_generate_key_nif},
    {"ec_verify_nif", 3, ucrypto_ec_verify_nif},
    {"ec_sign_nif", 2, ucrypto_ec_sign_nif},
    {"ec_get_public_key_nif", 1, ucrypto_ec_get_public_key_nif},
    {"ec_set_public_key_nif", 2, ucrypto_ec_set_public_key_nif},
    {"ec_get_private_key_nif", 1, ucrypto_ec_get_private_key_nif},
    {"ec_set_private_key_nif", 2, ucrypto_ec_set_private_key_nif},
    {"ec_delete_key_nif", 1, ucrypto_ec_delete_key_nif}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    if (0 != ucrypto_ec_on_load(env, priv_data, load_info))
        return 1;

    return 0;
}

static int on_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
    return on_load(env, priv_data, load_info);
}

ERL_NIF_INIT(ucrypto, nif_functions, on_load, /* reload */ NULL, on_upgrade, /* unload */ NULL);
