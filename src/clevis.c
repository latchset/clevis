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

#include "clevis.h"
#include "crypto.h"
#include "pin.h"
#include "pwd.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <getopt.h>

static const clevis_provision_f pfuncs = {
  .encrypt = crypto_encrypt,
};

static const clevis_acquire_f afuncs = {
  .decrypt = crypto_decrypt,
  .password = pwd
};

static int
provision(int argc, char *argv[])
{
  const char *output = NULL;
  clevis_buf_t *key = NULL;
  const char *type = NULL;
  json_error_t jerr = {};
  json_t *data = NULL;
  json_t *lay = NULL;
  pin_t *pin = NULL;
  size_t len = 0;
  char fmt = 'X';

  optind = 2;

  len = crypto_set_cipher("aes-128-gcm");
  if (len == 0 || !crypto_set_kdf_time("1.0"))
    goto error;

  for (int c; (c = getopt(argc, argv, "T:C:P:O:f:h")) != -1; ) {
    switch (c) {
    case 'T':
      if (!crypto_set_kdf_time(optarg)) {
	fprintf(stderr, "Invalid KDF time!\n");
	goto error;
      }
      break;

    case 'C':
      len = crypto_set_cipher(optarg);
      if (len == 0) {
	fprintf(stderr, "Invalid cipher!\n");
	goto error;
      }
      break;

    case 'P':
      if (type != NULL) {
	fprintf(stderr, "Pin layout already specified!\n");
	goto error;
      }

      lay = json_load_file(optarg, 0, &jerr);
      if (!lay) {
	lay = json_loads(optarg, 0, &jerr);
	if (!lay) {
	  fprintf(stderr, "Error loading layout: %s!\n", optarg);
	  goto error;
	}
      }

      type = json_string_value(json_object_get(lay, "type"));
      if (!type) {
	fprintf(stderr, "Invalid pin layout type!\n");
	goto error;
      }
      break;

    case 'O':
      output = optarg;
      break;

    case 'f':
      if (strlen(optarg) != 1) {
	fprintf(stderr, "Invalid format!\n");
	goto error;
      }

      switch (optarg[0]) {
      case 'b':
      case 'x':
      case 'X':
	fmt = optarg[0];
	break;

      default:
	fprintf(stderr, "Invalid format!\n");
	goto error;
      }
      break;

    default:
      goto usage;
    }
  }

  if (!output) {
    fprintf(stderr, "Output not specified!\n");
    goto usage;
  }

  if (!type) {
    fprintf(stderr, "Pin layout not specified!\n");
    goto usage;
  }

  key = clevis_buf_rand(len);
  if (!key) {
    fprintf(stderr, "Unable to create random key!\n");
    goto error;
  }

  if (!pin_name(lay)) {
    fprintf(stderr, "Unable to name pin!\n");
    goto error;
  }

  pin = pin_load(type);
  if (!pin) {
    fprintf(stderr, "Unable to load pin: %s!\n", type);
    goto error;
  }

  data = pin->pin->provision(&pfuncs, lay, key);
  pin_free(pin);
  if (!data)
    goto error;

  if (json_object_set(data, "name", json_object_get(lay, "name")) < 0)
    goto error;

  if (json_object_set(data, "type", json_object_get(lay, "type")) < 0)
    goto error;

  if (json_dump_file(data, output, JSON_COMPACT) < 0) {
    fprintf(stderr, "Error writing output to %s!\n", output);
    goto error;
  }

  switch (fmt) {
  case 'b':
    fwrite(key->buf, 1, key->len, stdout);
    break;

  case 'x':
  case 'X':
    for (size_t i = 0; i < key->len; i++)
      fprintf(stdout, fmt == 'x' ? "%02x" : "%02X", key->buf[i]);
    break;
  }

  clevis_buf_free(key);
  json_decref(data);
  json_decref(lay);
  return EXIT_SUCCESS;

error:
  clevis_buf_free(key);
  json_decref(data);
  json_decref(lay);
  return EXIT_FAILURE;

usage:
  fprintf(stderr, "Usage: %s provision [-h] "
	  "[-T seconds] [-C cipher] [-f format] -P pin -O output\n", argv[0]);
  return EXIT_FAILURE;
}

static int
acquire(int argc, char *argv[])
{
  const char *input = NULL;
  clevis_buf_t *key = NULL;
  json_error_t jerr = {};
  json_t *data = NULL;
  pin_t *pin = NULL;
  char fmt = 'X';

  optind = 2;

  for (int c; (c = getopt(argc, argv, "I:f:h")) != -1; ) {
    switch (c) {
    case 'I':
      input = optarg;
      break;

    case 'f':
      if (strlen(optarg) != 1) {
	fprintf(stderr, "Invalid format!\n");
	goto usage;
      }

      switch (optarg[0]) {
      case 'b':
      case 'x':
      case 'X':
	fmt = optarg[0];
	break;

      default:
	fprintf(stderr, "Invalid format!\n");
	goto usage;
      }
      break;

    default:
      goto usage;
    }
  }

  if (!input) {
    fprintf(stderr, "Input not specified!\n");
    goto usage;
  }

  data = json_load_file(input, JSON_DECODE_ANY, &jerr);
  if (!json_is_object(data)) {
    fprintf(stderr, "Error decoding %s!\n", input);
    json_decref(data);
    return EXIT_FAILURE;
  }

  if (!json_is_string(json_object_get(data, "type"))) {
    fprintf(stderr, "Input data missing type field!\n");
    json_decref(data);
    return EXIT_FAILURE;
  }

  pin = pin_load(json_string_value(json_object_get(data, "type")));
  if (!pin) {
    fprintf(stderr, "Unable to load pin: %s!\n",
	    json_string_value(json_object_get(data, "type")));
    json_decref(data);
    return EXIT_FAILURE;
  }

  key = pin->pin->acquire(&afuncs, data);
  json_decref(data);
  pin_free(pin);
  if (!key)
    return EXIT_FAILURE;

  switch (fmt) {
  case 'b':
    fwrite(key->buf, 1, key->len, stdout);
    break;

  case 'x':
  case 'X':
    for (size_t i = 0; i < key->len; i++)
      fprintf(stdout, fmt == 'x' ? "%02x" : "%02X", key->buf[i]);
    break;
  }

  clevis_buf_free(key);
  return EXIT_SUCCESS;

usage:
  fprintf(stderr, "Usage: %s acquire [-h] [-f format] -i input\n", argv[0]);
  return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
  clevis_buf_t *seed = NULL;
  int r = EXIT_FAILURE;

  seed = clevis_buf_rand(1024 * 16);
  if (!seed) {
    fprintf(stderr, "Unable to seed PRNG!\n");
    goto egress;
  }

  OpenSSL_add_all_algorithms();
  RAND_seed(seed->buf, seed->len);
  clevis_buf_free(seed);

  if (argc > 1) {
    if (strcmp("provision", argv[1]) == 0) {
      r = provision(argc, argv);
      goto egress;
    }

    if (strcmp("acquire", argv[1]) == 0) {
      r = acquire(argc, argv);
      goto egress;
    }
  }

  fprintf(stderr, "Usage: %s [provision|acquire] ...\n", argv[0]);

egress:
  EVP_cleanup();
  return r;
}
