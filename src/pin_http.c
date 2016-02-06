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

/* FIXME: this code copies the key into unprotected memory. */

#define _GNU_SOURCE
#include "clevis.h"

#include <string.h>
#include <curl/curl.h>

struct state {
  clevis_buf_t *buf;
  size_t pos;
};

struct header {
  const char *fmt;
  const char *hdr;
};

static struct header content_types[] = {
    { "custodia", "Content-Type: application/json" },
    { "binary", "Content-Type: application/octet-stream" },
    {}
};

static struct header accepts[] = {
    { "custodia", "Accept: application/json" },
    { "binary", "Accept: application/octet-stream" },
    {}
};

static struct curl_slist *
header(const char *format, struct header *table)
{
  for (int i = 0; table[i].fmt; i++) {
    if (strcasecmp(format, table[i].fmt) == 0)
      return curl_slist_append(NULL, table[i].hdr);
  }

  return NULL;
}

static size_t
read_callback(void *ptr, size_t size, size_t nmemb, void *misc)
{
  struct state *state = misc;
  const size_t want = size * nmemb;
  const size_t left = state->buf->len - state->pos;
  const size_t len = want > left ? left : want;

  if (len > 0)
    memcpy(ptr, state->buf->buf + state->pos, len);

  state->pos += len;
  return len;
}

static clevis_buf_t *
unparse(clevis_buf_t *key, const char *format)
{
  clevis_buf_t *buf = NULL;
  json_t *tmp = NULL;
  char *txt = NULL;

  if (strcasecmp(format, "custodia") != 0)
    return clevis_buf_make(key->len, key->buf);

  tmp = json_object();
  if (!tmp)
    goto error;

  if (json_object_set_new(tmp, "type", json_string("simple")) < 0)
    goto error;


  if (json_object_set_new(tmp, "value", clevis_buf_encode(key)) < 0)
    goto error;

  txt = json_dumps(tmp, JSON_COMPACT);
  if (!txt)
    goto error;

  buf = clevis_buf_make(strlen(txt), (uint8_t *) txt);
  free(txt);

error:
  json_decref(tmp);
  return buf;
}

static clevis_buf_t *
parse(const clevis_buf_t *buf, const char *format)
{
  clevis_buf_t *key = NULL;
  json_error_t jerr = {};
  json_t *tmp = NULL;

  if (strcasecmp(format, "custodia") != 0)
    return clevis_buf_make(buf->len, buf->buf);

  tmp = json_loadb((const char *) buf->buf, buf->len, 0, &jerr);
  if (!tmp)
    return NULL;

  key = clevis_buf_decode(json_object_get(tmp, "value"));
  json_decref(tmp);
  return key;
}

static json_t *
provision(const clevis_provision_f *funcs,
          const json_t *cfg, const clevis_buf_t *key)
{
  struct curl_slist *headers = NULL;
  clevis_buf_t *okey = NULL;
  struct state state = {};
  const char *url = NULL;
  json_t *data = NULL;
  json_t *tmp = NULL;
  CURL *curl = NULL;
  CURLcode res;

  /* Setup the return data. */
  data = json_object();
  if (!data)
    goto error;

  tmp = json_object_get(cfg, "url");
  if (!json_is_string(tmp))
    goto error;
  url = json_string_value(tmp);
  if (strcasestr(url, "https://") != url)
    goto error;

  if (json_object_set(data, "url", tmp) < 0)
    goto error;

  if (json_object_set_new(data, "format", json_string("binary")) < 0)
    goto error;
  tmp = json_object_get(cfg, "format");
  if (json_is_string(tmp) && json_object_set(data, "format", tmp) < 0)
    goto error;

  okey = clevis_buf_rand(key->len);
  if (!okey)
    goto error;

  if (json_object_set_new(data, "ct", funcs->encrypt(okey, key)) < 0)
    goto error;

  /* Setup the transfer buffer. */
  tmp = json_object_get(cfg, "format");
  headers = header(json_string_value(tmp), content_types);
  state.buf = unparse(okey, json_string_value(tmp));
  if (!state.buf)
    goto error;

  /* Use HTTP PUT to store the key. */
  curl = curl_easy_init();
  if (!curl)
    goto error;

  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) state.buf->len);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_READDATA, &state);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    goto error;

  curl_slist_free_all(headers);
  clevis_buf_free(state.buf);
  curl_easy_cleanup(curl);
  clevis_buf_free(okey);
  return data;

error:
  curl_slist_free_all(headers);
  clevis_buf_free(state.buf);
  curl_easy_cleanup(curl);
  clevis_buf_free(okey);
  json_decref(data);
  return NULL;
}

static size_t
write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
  clevis_buf_t **bufp = userp;
  clevis_buf_t *tmp = NULL;

  if (!*bufp) {
    *bufp = clevis_buf_make(size * nmemb, buffer);
    return *bufp ? (*bufp)->len : 0;
  }

  tmp = clevis_buf_make(size * nmemb + (*bufp)->len, NULL);
  if (!tmp)
    return 0;

  memcpy(tmp->buf, (*bufp)->buf, (*bufp)->len);
  memcpy(tmp->buf + (*bufp)->len, buffer, size * nmemb);
  clevis_buf_free(*bufp);
  *bufp = tmp;
  return size * nmemb;
}

static clevis_buf_t *
acquire(const clevis_acquire_f *funcs, const json_t *data)
{
  struct curl_slist *headers = NULL;
  clevis_buf_t *okey = NULL;
  clevis_buf_t *ikey = NULL;
  clevis_buf_t *buf = NULL;
  const json_t *url = NULL;
  CURL *curl = NULL;
  CURLcode res;

  headers = header(json_string_value(json_object_get(data, "format")), accepts);

  url = json_object_get(data, "url");
  if (!json_is_string(url))
    return NULL;

  curl = curl_easy_init();
  if (!curl)
    goto error;

  curl_easy_setopt(curl, CURLOPT_URL, json_string_value(url));
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    goto error;

  okey = parse(buf, json_string_value(json_object_get(data, "format")));
  if (!okey)
    goto error;

  ikey = funcs->decrypt(okey, json_object_get(data, "ct"));

error:
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  clevis_buf_free(okey);
  clevis_buf_free(buf);
  return ikey;
}

clevis_pin_f CLEVIS_PIN = {
  .provision = provision,
  .acquire = acquire
};
