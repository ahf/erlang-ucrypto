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
#include "ucrypto_ripemd160.h"

#include <string.h>
#include <openssl/ripemd.h>

static const int ripemd160_length = 160 / 8;

ERL_NIF_TERM ucrypto_ripemd160_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary binary;
    ERL_NIF_TERM result;

    if (! enif_inspect_iolist_as_binary(env, argv[0], &binary))
        return enif_make_badarg(env);

    RIPEMD160(binary.data, binary.size, enif_make_new_binary(env, ripemd160_length, &result));

    return result;
}

ERL_NIF_TERM ucrypto_ripemd160_init_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM result;

    RIPEMD160_Init((RIPEMD160_CTX *)enif_make_new_binary(env, sizeof(RIPEMD160_CTX), &result));

    return result;
}

ERL_NIF_TERM ucrypto_ripemd160_update_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    RIPEMD160_CTX *new_context;
    ErlNifBinary context_binary, data_binary;
    ERL_NIF_TERM result;

    if (! enif_inspect_binary(env, argv[0], &context_binary) || context_binary.size != sizeof(RIPEMD160_CTX))
        return enif_make_badarg(env);

    if (! enif_inspect_iolist_as_binary(env, argv[1], &data_binary))
        return enif_make_badarg(env);

    new_context = (RIPEMD160_CTX *)enif_make_new_binary(env, sizeof(RIPEMD160_CTX), &result);
    memcpy(new_context, context_binary.data, sizeof(RIPEMD160_CTX));

    RIPEMD160_Update(new_context, data_binary.data, data_binary.size);

    return result;
}

ERL_NIF_TERM ucrypto_ripemd160_final_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary context_binary;
    RIPEMD160_CTX context_clone;
    ERL_NIF_TERM result;

    if (! enif_inspect_binary(env, argv[0], &context_binary) || context_binary.size != sizeof(RIPEMD160_CTX))
        return enif_make_badarg(env);

    memcpy(&context_clone, context_binary.data, sizeof(RIPEMD160_CTX));
    RIPEMD160_Final(enif_make_new_binary(env, ripemd160_length, &result), &context_clone);

    return result;
}
