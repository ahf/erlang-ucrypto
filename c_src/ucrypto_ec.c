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

#include <assert.h>
#include <stdbool.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

struct ec_key_handle {
    EC_KEY *key;
};

static ErlNifResourceType *ec_key_resource;

static ERL_NIF_TERM ATOM_OK;
static ERL_NIF_TERM ATOM_ERROR;
static ERL_NIF_TERM ATOM_TRUE;
static ERL_NIF_TERM ATOM_FALSE;

/* Curves. */
static ERL_NIF_TERM ATOM_secp112r1;
static ERL_NIF_TERM ATOM_secp112r2;
static ERL_NIF_TERM ATOM_secp128r1;
static ERL_NIF_TERM ATOM_secp128r2;
static ERL_NIF_TERM ATOM_secp160k1;
static ERL_NIF_TERM ATOM_secp160r1;
static ERL_NIF_TERM ATOM_secp160r2;
static ERL_NIF_TERM ATOM_secp192k1;
static ERL_NIF_TERM ATOM_secp224k1;
static ERL_NIF_TERM ATOM_secp224r1;
static ERL_NIF_TERM ATOM_secp256k1;
static ERL_NIF_TERM ATOM_secp384r1;
static ERL_NIF_TERM ATOM_secp521r1;

static void ec_key_handle_cleanup(ErlNifEnv *env, void *data)
{
    if (! data)
        return;

    struct ec_key_handle *handle = data;
    EC_KEY_free(handle->key);
    handle->key = NULL;
}

int ucrypto_ec_on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    ec_key_resource = enif_open_resource_type(env, NULL, "ucrypto_ec_resource", &ec_key_handle_cleanup, (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER), NULL);

    ATOM(ATOM_OK, "ok");
    ATOM(ATOM_ERROR, "error");
    ATOM(ATOM_TRUE, "true");
    ATOM(ATOM_FALSE, "false");

    ATOM(ATOM_secp112r1, "secp112r1");
    ATOM(ATOM_secp112r2, "secp112r2");
    ATOM(ATOM_secp128r1, "secp128r1");
    ATOM(ATOM_secp128r2, "secp128r2");
    ATOM(ATOM_secp160k1, "secp160k1");
    ATOM(ATOM_secp160r1, "secp160r1");
    ATOM(ATOM_secp160r2, "secp160r2");
    ATOM(ATOM_secp192k1, "secp192k1");
    ATOM(ATOM_secp224k1, "secp224k1");
    ATOM(ATOM_secp224r1, "secp224r1");
    ATOM(ATOM_secp256k1, "secp256k1");
    ATOM(ATOM_secp384r1, "secp384r1");
    ATOM(ATOM_secp521r1, "secp521r1");

    return 0;
}

ERL_NIF_TERM ucrypto_ec_new_by_curve_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int nid;
    struct ec_key_handle *handle;
    ERL_NIF_TERM ec_key;

    ERL_NIF_TERM curve = argv[0];

    if (ATOM_secp112r1 == curve)
        nid = NID_secp112r1;
    else if (ATOM_secp112r2 == curve)
        nid = NID_secp112r2;
    else if (ATOM_secp128r1 == curve)
        nid = NID_secp128r1;
    else if (ATOM_secp128r2 == curve)
        nid = NID_secp128r2;
    else if (ATOM_secp160k1 == curve)
        nid = NID_secp160k1;
    else if (ATOM_secp160r1 == curve)
        nid = NID_secp160r1;
    else if (ATOM_secp160r2 == curve)
        nid = NID_secp160r2;
    else if (ATOM_secp192k1 == curve)
        nid = NID_secp192k1;
    else if (ATOM_secp224k1 == curve)
        nid = NID_secp224k1;
    else if (ATOM_secp224r1 == curve)
        nid = NID_secp224r1;
    else if (ATOM_secp256k1 == curve)
        nid = NID_secp256k1;
    else if (ATOM_secp384r1 == curve)
        nid = NID_secp384r1;
    else if (ATOM_secp521r1 == curve)
        nid = NID_secp521r1;
    else
        return enif_make_badarg(env);

    handle = enif_alloc_resource(ec_key_resource, sizeof(struct ec_key_handle));
    handle->key = EC_KEY_new_by_curve_name(nid);

    if (! handle->key) {
        enif_release_resource(handle);
        return ATOM_ERROR;
    }

    ec_key = enif_make_resource(env, handle);
    enif_release_resource(handle);

    return ec_key;
}

ERL_NIF_TERM ucrypto_ec_generate_key_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    struct ec_key_handle *handle = NULL;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    if (! EC_KEY_generate_key(handle->key))
        return ATOM_ERROR;

    return ATOM_OK;
}

ERL_NIF_TERM ucrypto_ec_verify_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    struct ec_key_handle *handle = NULL;
    ErlNifBinary data;
    ErlNifBinary signature;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    if (! enif_inspect_iolist_as_binary(env, argv[1], &data))
        return enif_make_badarg(env);

    if (! enif_inspect_iolist_as_binary(env, argv[2], &signature))
        return enif_make_badarg(env);

    if (1 == ECDSA_verify(0, data.data, data.size, signature.data, signature.size, handle->key))
        return ATOM_TRUE;

    return ATOM_FALSE;
}

ERL_NIF_TERM ucrypto_ec_sign_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned int length;
    struct ec_key_handle *handle = NULL;
    ErlNifBinary data;
    ErlNifBinary signature;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    if (! enif_inspect_iolist_as_binary(env, argv[1], &data))
        return enif_make_badarg(env);

    enif_alloc_binary(ECDSA_size(handle->key), &signature);

    if (! ECDSA_sign(0, data.data, data.size, signature.data, &length, handle->key))
        return ATOM_ERROR;

    enif_realloc_binary(&signature, length);

    return enif_make_binary(env, &signature);
}

ERL_NIF_TERM ucrypto_ec_get_public_key_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int length;
    struct ec_key_handle *handle = NULL;
    ErlNifBinary public_key;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    length = i2o_ECPublicKey(handle->key, NULL);

    if (! length)
        return ATOM_ERROR;

    enif_alloc_binary(length, &public_key);

    if (i2o_ECPublicKey(handle->key, &public_key.data) != length)
        return ATOM_ERROR;

    return enif_make_binary(env, &public_key);
}

ERL_NIF_TERM ucrypto_ec_set_public_key_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    struct ec_key_handle *handle = NULL;
    ErlNifBinary public_key;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    if (! enif_inspect_iolist_as_binary(env, argv[1], &public_key))
        return enif_make_badarg(env);

    if (! o2i_ECPublicKey(&handle->key, (const unsigned char **)&public_key.data, public_key.size))
        return ATOM_ERROR;

    return ATOM_OK;
}

ERL_NIF_TERM ucrypto_ec_get_private_key_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int length;
    struct ec_key_handle *handle = NULL;
    ErlNifBinary private_key;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    length = i2d_ECPrivateKey(handle->key, NULL);

    if (! length)
        return ATOM_ERROR;

    enif_alloc_binary(length, &private_key);

    if (i2d_ECPrivateKey(handle->key, &private_key.data) != length)
        return ATOM_ERROR;

    return enif_make_binary(env, &private_key);
}

ERL_NIF_TERM ucrypto_ec_set_private_key_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    struct ec_key_handle *handle = NULL;
    ErlNifBinary private_key;

    if (! enif_get_resource(env, argv[0], ec_key_resource, (void **)&handle))
        return enif_make_badarg(env);

    if (! enif_inspect_iolist_as_binary(env, argv[1], &private_key))
        return enif_make_badarg(env);

    if (! d2i_ECPrivateKey(&handle->key, (const unsigned char **)&private_key.data, private_key.size))
        return ATOM_ERROR;

    return ATOM_OK;
}
