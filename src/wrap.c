/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wrap.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

static const EVP_CIPHER *
get_cipher(const json_t *req)
{
  json_t *cipher = NULL;

  cipher = json_object_get(req, "cipher");
  if (!json_is_string(cipher))
    return NULL;

  if (strcmp(json_string_value(cipher), "A128GCM") == 0)
    return EVP_aes_128_gcm();

  if (strcmp(json_string_value(cipher), "A192GCM") == 0)
    return EVP_aes_192_gcm();

  if (strcmp(json_string_value(cipher), "A256GCM") == 0)
    return EVP_aes_256_gcm();

  return NULL;
}

size_t
wrap_defaults(json_t *data, size_t key_len)
{
  const EVP_CIPHER *cipher = NULL;
  const char *alg = NULL;
  int len = 0;

  switch ((key_len + 7) / 8) {
  case 2: alg = "A128GCM"; break;
  case 3: alg = "A192GCM"; break;
  case 4: alg = "A256GCM"; break;
  default: return 0;
  }

  if (json_object_put_new(data, "cipher", json_string(alg)) < 0)
    return 0;

  cipher = get_cipher(data);
  if (!cipher)
    return 0;

  len = EVP_CIPHER_key_length(cipher);
  if (len < (int) key_len)
    return 0;

  return len;
}

buf_t *
wrap_enc(const json_t *data, buf_t *key, const char *aad, const buf_t *pt)
{
  const EVP_CIPHER *cipher = NULL;
  buf_auto_t *ct = NULL;
  buf_auto_t *iv = NULL;
  EVP_CIPHER_CTX *ctx;
  int bsize = 0;
  int outl = 0;
  int len = 0;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return NULL;

  cipher = get_cipher(data);
  if (!cipher)
    goto error;
  bsize = EVP_CIPHER_block_size(cipher);

  if ((int) key->len != EVP_CIPHER_key_length(cipher))
    goto error;

  iv = buf_random(EVP_CIPHER_iv_length(cipher));
  if (!iv)
    goto error;

  ct = buf_new(NULL, iv->len * 2 + pt->len + bsize * 2);
  if (!ct)
    goto error;

  memcpy(ct->buf, iv->buf, iv->len);
  if (EVP_EncryptInit(ctx, cipher, key->buf, ct->buf) <= 0)
    goto error;

  if (aad && EVP_EncryptUpdate(ctx, NULL, &outl,
                               (uint8_t *) aad, strlen(aad)) <= 0)
    goto error;

  outl = 0;
  if (EVP_EncryptUpdate(ctx, &ct->buf[iv->len], &outl, pt->buf, pt->len) <= 0)
    goto error;

  len = iv->len + outl;
  outl = 0;
  if (EVP_EncryptFinal(ctx, &ct->buf[len], &outl) <= 0)
    goto error;

  len += outl;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                          iv->len, &ct->buf[len]) <= 0)
    goto error;

  EVP_CIPHER_CTX_free(ctx);
  return buf_new(ct->buf, len + iv->len);

error:
  ERR_print_errors_fp(stderr);
  EVP_CIPHER_CTX_free(ctx);
  return NULL;
}

buf_t *
wrap_dec(const json_t *data, buf_t *key, const char *aad, const buf_t *ct)
{
  const EVP_CIPHER *cipher = NULL;
  buf_auto_t *pt = NULL;
  EVP_CIPHER_CTX *ctx;
  int ivlen = 0;
  int outl = 0;
  int len = 0;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return NULL;

  cipher = get_cipher(data);
  if (!cipher)
    goto error;

  ivlen = EVP_CIPHER_iv_length(cipher);
  if ((int) ct->len < ivlen * 2)
    goto error;

  if ((int) key->len != EVP_CIPHER_key_length(cipher))
    goto error;

  pt = buf_new(NULL, ct->len);
  if (!pt)
    goto error;

  if (EVP_DecryptInit(ctx, cipher, key->buf, ct->buf) <= 0)
    goto error;

  if (aad && EVP_DecryptUpdate(ctx, NULL, &outl,
                               (uint8_t *) aad, strlen(aad)) <= 0)
    goto error;

  outl = 0;
  if (EVP_DecryptUpdate(ctx, pt->buf, &outl, &ct->buf[ivlen],
                        ct->len - ivlen * 2) <= 0)
    goto error;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ivlen,
                          (void *) &ct->buf[ct->len - ivlen]) <= 0)
    goto error;

  len = outl;
  outl = 0;
  if (EVP_DecryptFinal(ctx, &pt->buf[len], &outl) <= 0)
    goto error;

  len += outl;

  EVP_CIPHER_CTX_free(ctx);
  return buf_new(pt->buf, len);

error:
  EVP_CIPHER_CTX_free(ctx);
  return NULL;
}
