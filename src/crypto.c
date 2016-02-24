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

#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <string.h>

#define ITER_MIN 1
#define SALT_MIN 8
#define TIME_MIN 1.0

static const EVP_CIPHER *cipher = NULL;
static double kdftime = TIME_MIN;

static const struct {
  const char *name;
  int nid;
} kdfs[] = {
  {"1.2.840.113549.2.9", NID_sha256},
  {"1.2.840.113549.2.10", NID_sha384},
  {"1.2.840.113549.2.11", NID_sha512},
  {}
};

static const EVP_MD *
str2md(const char *str)
{
  for (size_t i = 0; kdfs[i].name; i++) {
    if (strcasecmp(str, kdfs[i].name) == 0)
      return EVP_get_digestbynid(kdfs[i].nid);
  }

  return NULL;
}

static const EVP_MD *
json2md(const json_t *json)
{
  if (!json_is_string(json))
    return NULL;

  return str2md(json_string_value(json));
}

static json_t *
md2json(const EVP_MD *md)
{
  for (size_t i = 0; kdfs[i].name; i++) {
    if (kdfs[i].nid == EVP_MD_nid(md))
      return json_string(kdfs[i].name);
  }

  return NULL;
}

static const EVP_CIPHER *
str2cipher(const char *str)
{
  int nid;

  switch (nid = OBJ_txt2nid(str)) {
  case NID_aes_128_gcm: break;
  case NID_aes_192_gcm: break;
  case NID_aes_256_gcm: break;
  default: return NULL;
  }

  return EVP_get_cipherbynid(nid);
}

static const EVP_CIPHER *
json2cipher(const json_t *json)
{
  if (!json_is_string(json))
    return NULL;

  return str2cipher(json_string_value(json));
}

static json_t *
cipher2json(const EVP_CIPHER *c)
{
  ASN1_OBJECT *obj = NULL;
  int len = 0;

  int nid = EVP_CIPHER_nid(c);
  if (nid == NID_undef)
    return NULL;

  obj = OBJ_nid2obj(nid);
  if (!obj)
    return NULL;

  len = OBJ_obj2txt(NULL, 0, obj, true);
  if (len < 1) {
    ASN1_OBJECT_free(obj);
    return NULL;
  }

  char buf[len+1];

  memset(buf, 0, sizeof(buf));
  len = OBJ_obj2txt(buf, sizeof(buf), obj, true);
  ASN1_OBJECT_free(obj);
  if (len + 1 != (int) sizeof(buf))
    return NULL;

  return json_string(buf);
}

static int
get_time(double *time)
{
  struct timespec t;

  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) < 0)
    return errno;

  *time = ((double) t.tv_nsec) / 1000000000;
  *time += t.tv_sec;
  return 0;
}

static json_t *
encrypt(const clevis_buf_t *key, const clevis_buf_t *pt)
{
  EVP_CIPHER_CTX *ctx = NULL;
  clevis_buf_t *buf = NULL;
  clevis_buf_t *ct = NULL;
  clevis_buf_t *iv = NULL;
  json_t *out = NULL;
  int bsize = 0;
  int outl = 0;
  int len = 0;

  if (!cipher)
    return NULL;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return NULL;

  bsize = EVP_CIPHER_block_size(cipher);

  if ((int) key->len != EVP_CIPHER_key_length(cipher))
    goto egress;

  iv = clevis_buf_rand(EVP_CIPHER_iv_length(cipher));
  if (!iv)
    goto egress;

  ct = clevis_buf_make(iv->len * 2 + pt->len + bsize * 2, NULL);
  if (!ct)
    goto egress;

  memcpy(ct->buf, iv->buf, iv->len);
  if (EVP_EncryptInit(ctx, cipher, key->buf, iv->buf) <= 0)
    goto egress;

  outl = 0;
  if (EVP_EncryptUpdate(ctx, &ct->buf[iv->len], &outl, pt->buf, pt->len) <= 0)
    goto egress;

  len = iv->len + outl;
  outl = 0;
  if (EVP_EncryptFinal(ctx, &ct->buf[len], &outl) <= 0)
    goto egress;

  len += outl;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                          iv->len, &ct->buf[len]) <= 0)
    goto egress;

  buf = clevis_buf_make(len + iv->len, ct->buf);
  if (!buf)
    goto egress;

  out = clevis_buf_encode(buf);
  clevis_buf_free(buf);

egress:
  EVP_CIPHER_CTX_free(ctx);
  clevis_buf_free(ct);
  clevis_buf_free(iv);
  return out;
}

static clevis_buf_t *
decrypt(const EVP_CIPHER *cphr, const clevis_buf_t *key, const clevis_buf_t *buf)
{
  EVP_CIPHER_CTX *ctx = NULL;
  clevis_buf_t *out = NULL;
  clevis_buf_t *pt = NULL;
  int ivlen = 0;
  int outl = 0;
  int len = 0;

  if (!buf)
    return NULL;

  pt = clevis_buf_make(buf->len, NULL);
  if (!pt)
    goto egress;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    goto egress;

  ivlen = EVP_CIPHER_iv_length(cphr);
  if ((int) buf->len < ivlen * 2)
    goto egress;

  if ((int) key->len != EVP_CIPHER_key_length(cphr))
    goto egress;

  if (EVP_DecryptInit(ctx, cphr, key->buf, buf->buf) <= 0)
    goto egress;

  outl = 0;
  if (EVP_DecryptUpdate(ctx, pt->buf, &outl, &buf->buf[ivlen],
			buf->len - ivlen * 2) <= 0)
    goto egress;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ivlen,
                          (void *) &buf->buf[buf->len - ivlen]) <= 0)
    goto egress;

  len = outl;
  outl = 0;
  if (EVP_DecryptFinal(ctx, &pt->buf[len], &outl) <= 0)
    goto egress;

  out = clevis_buf_make(len + outl, pt->buf);

egress:
  EVP_CIPHER_CTX_free(ctx);
  clevis_buf_free(pt);
  return out;
}

static bool
pbkdf2(const EVP_MD *md, json_int_t iter, const clevis_buf_t *key,
       const clevis_buf_t *salt, clevis_buf_t *dkey)
{
  return PKCS5_PBKDF2_HMAC((char *) key->buf, key->len, salt->buf, salt->len,
			   iter, md, dkey->len, dkey->buf) > 0;
}

size_t
crypto_set_cipher(const char *str)
{
  const EVP_CIPHER *c = str2cipher(str);
  return c ? EVP_CIPHER_key_length(cipher = c) : 0;
}

bool
crypto_set_kdf_time(const char *str)
{
  double d;

  d = strtod(str, NULL);
  if (d > TIME_MIN)
    kdftime = d;

  return kdftime == d;
}

json_t *
crypto_encrypt(const clevis_buf_t *key, const clevis_buf_t *pt)
{
  clevis_buf_t *dkey = NULL;
  clevis_buf_t *salt = NULL;
  const EVP_MD *md = NULL;
  json_t *ct = NULL;
  int iter = 1024;

  if (!cipher)
    return NULL;

  switch (EVP_CIPHER_key_length(cipher)) {
  case 128 / 8: md = EVP_sha256(); break;
  case 192 / 8: md = EVP_sha384(); break;
  case 256 / 8: md = EVP_sha512(); break;
  default: return NULL;
  }

  ct = json_object();
  if (!ct)
    return NULL;

  if (json_object_set_new(ct, "cipher", cipher2json(cipher)) < 0)
    goto error;

  if (json_object_set_new(ct, "kdf", md2json(md)) < 0)
    goto error;

  salt = clevis_buf_rand(EVP_CIPHER_key_length(cipher));
  if (!salt)
    goto error;

  if (json_object_set_new(ct, "salt", clevis_buf_encode(salt)) < 0)
    goto error;

  dkey = clevis_buf_make(EVP_CIPHER_key_length(cipher), NULL);
  if (!dkey)
    goto error;

  for (double e = 0, s = 0; e - s < kdftime; iter *= kdftime * 1.5 / (e - s)) {
    if (json_object_set_new(ct, "iter", json_integer(iter)) < 0)
      goto error;

    if (get_time(&s) != 0)
      goto error;

    if (!pbkdf2(md, iter, key, salt, dkey))
      goto error;

    if (get_time(&e) != 0 || e - s == 0)
      goto error;
  }

  if (json_object_set_new(ct, "ct", encrypt(dkey, pt)) < 0)
    goto error;

  clevis_buf_free(dkey);
  clevis_buf_free(salt);
  return ct;

error:
  clevis_buf_free(dkey);
  clevis_buf_free(salt);
  json_decref(ct);
  return NULL;
}

clevis_decrypt_result_t
crypto_decrypt(const clevis_buf_t *key, const json_t *ct)
{
  const EVP_CIPHER *cphr = NULL;
  const json_t *iter = NULL;
  const EVP_MD *md = NULL;
  clevis_buf_t *dkey = NULL;
  clevis_buf_t *salt = NULL;
  clevis_buf_t *ct_decoded = NULL;
  clevis_decrypt_result_t result = { DECRYPT_FAIL_STOP, NULL };

  cphr = json2cipher(json_object_get(ct, "cipher"));
  if (!cphr)
    return result;

  md = json2md(json_object_get(ct, "kdf"));
  if (!md)
    return result;

  iter = json_object_get(ct, "iter");
  if (!json_is_integer(iter) || json_integer_value(iter) <= 0)
    return result;

  salt = clevis_buf_decode(json_object_get(ct, "salt"));
  if (!salt)
    return result;

  ct_decoded = clevis_buf_decode(json_object_get(ct, "ct"));
  if (!ct_decoded)
    goto egress;

  result.result = DECRYPT_FAIL_TRYAGAIN;
  dkey = clevis_buf_make(EVP_CIPHER_key_length(cphr), NULL);
  if (!dkey)
    goto egress;

  if (!pbkdf2(md, json_integer_value(iter), key, salt, dkey))
    goto egress;

  result.pt = decrypt(cphr, dkey, ct_decoded);
  if (result.pt != NULL)
    result.result = DECRYPT_SUCCESS;

egress:
  clevis_buf_free(dkey);
  clevis_buf_free(salt);
  clevis_buf_free(ct_decoded);
  return result;
}
