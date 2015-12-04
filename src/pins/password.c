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

#include "../json.h"
#include "../kdf.h"
#include "../mem.h"

#include <openssl/evp.h>

#include <error.h>
#include <string.h>
#include <unistd.h>

static buf_t *
get_password(void)
{
  char *password = NULL;
  buf_t *tmp = NULL;

  password = getpass("Password: ");
  if (!password)
    return NULL;

  tmp = buf_new((uint8_t *) password, strlen(password));
  memset(password, 0, strlen(password));
  return tmp;
}

int
main(int argc, char *argv[])
{
  buf_auto_t *password = NULL;
  const char *command = NULL;
  const char *branch = NULL;
  json_auto_t *req = NULL;
  json_auto_t *rep = NULL;
  buf_auto_t *key = NULL;
  json_error_t err = {};

  json_set_alloc_funcs(mem_malloc, mem_free);
  OpenSSL_add_all_algorithms();

  for (int c; (c = getopt(argc, argv, "hd:")) != -1; ) {
    switch (c) {
    case 'd': break;
    default: goto usage;
    }
  }

  if (argc - optind != 2)
    goto usage;

  command = argv[1];
  branch = argv[2];

  if (strcmp(command, "provision") != 0 && strcmp(command, "acquire") != 0)
    error(EXIT_FAILURE, 0, "Command must be provision or acquire: %s", branch);

  req = json_loadf(stdin, 0, &err);
  if (!json_is_object(req))
    error(EXIT_FAILURE, 0, "Input must be a JSON object: %s", branch);

  if (strcmp(command, "acquire") == 0) {
    password = get_password();
    if (!password)
      error(EXIT_FAILURE, 0, "Error getting password: %s", branch);

    key = kdf(req, password);
    if (!key)
      error(EXIT_FAILURE, 0, "Error performing KDF: %s", branch);

    rep = json_binary(key);
  } else {
    json_auto_t *data = NULL;
    json_t *params = NULL;
    json_t *size = NULL;

    size = json_object_get(req, "size");
    if (!json_is_integer(size))
      error(EXIT_FAILURE, 0, "Size must be an integer: %s", branch);

    data = json_object();
    if (!json_is_object(data))
      error(EXIT_FAILURE, 0, "Error creating data: %s", branch);

    params = json_object_fetch(req, "cfg.kdf");
    if (params) {
      if (json_object_set(data, "kdf", params) < 0)
        error(EXIT_FAILURE, 0, "Error setting kdf parameters: %s", branch);
    }

    if (!kdf_defaults(data, json_integer_value(size), OID_SHA512, 32768))
      error(EXIT_FAILURE, 0, "Error setting KDF defaults: %s", branch);

    password = get_password();
    if (!password)
      error(EXIT_FAILURE, 0, "Error getting password: %s", branch);

    key = kdf(data, password);
    if (!key)
      error(EXIT_FAILURE, 0, "Error performing KDF: %s", branch);

    rep = json_object();
    if (!rep)
      error(EXIT_FAILURE, 0, "Error creating reply object: %s", branch);

    if (json_object_set_new(rep, "key", json_binary(key)) < 0)
      error(EXIT_FAILURE, 0, "Error settings key in reply: %s", branch);

    if (json_object_set(rep, "data", data) < 0)
      error(EXIT_FAILURE, 0, "Error settings data in reply: %s", branch);
  }

  if (json_dumpf(rep, stdout, JSON_ENCODE_ANY) < 0)
    error(EXIT_FAILURE, 0, "Error writing output: %s", branch);

  EVP_cleanup();
  return EXIT_SUCCESS;

usage:
  fprintf(stderr, "Usage: %s [-h] [-d pindir] COMMAND BRANCH\n", argv[0]);
  EVP_cleanup();
  return EXIT_FAILURE;
}
