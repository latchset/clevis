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

#define _GNU_SOURCE
#include "ops.h"
#include "mem.h"

#include <openssl/evp.h>

#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>

#include <error.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
  json_auto_t *data = NULL;
  const char *attr = NULL;
  const char *file = NULL;
  const char *cmd = NULL;
  buf_auto_t *key = NULL;
  json_error_t jerr = {};
  char fmt = 'X';

  json_set_alloc_funcs(mem_malloc, mem_free);
  OpenSSL_add_all_algorithms();

  for (int c; (c = getopt(argc, argv, "hf:x:")) != -1; ) {
    switch (c) {
    case 'f':
      if (strlen(optarg) != 1)
	goto usage;

      switch (optarg[0]) {
      case 'b':
      case 'x':
      case 'X':
	fmt = optarg[0];
	break;

      default:
        goto usage;
      }

    case 'x':
      attr = optarg;
      break;

    default:
      goto usage;
    }
  }

  cmd = argv[optind++];
  if (!cmd)
    goto usage;

  file = argv[optind++];
  if (!file)
    goto usage;

  if (strcmp(cmd, "provision") == 0) {
    const char *bytes = NULL;
    const char *conf = NULL;
    json_auto_t *cfg = NULL;
    long int nbytes = 0;

    bytes = argv[optind++];
    if (!bytes)
      goto usage;

    conf = argv[optind++];
    if (!conf)
      goto usage;

    nbytes = strtol(bytes, NULL, 10);
    if (nbytes < 1 || nbytes == LONG_MAX)
      goto usage;

    cfg = json_load_file(conf, 0, &jerr);
    if (!json_is_object(cfg)) {
      cfg = json_loads(conf, 0, &jerr);
      if (!json_is_object(cfg))
        goto usage;
    }

    key = buf_random(nbytes);
    if (!key)
      error(EXIT_FAILURE, 0, "Unable to create random key");

    data = ops_provision("0", cfg, key);
    if (!data)
      error(EXIT_FAILURE, 0, "Error calling ops_provision()");

    if (!attr) {
      if (json_dump_file(data, file, JSON_ENCODE_ANY | JSON_COMPACT) < 0)
        error(EXIT_FAILURE, 0, "Error calling json_dump_file()");
    } else {
      char *tmp;

      tmp = json_dumps(data, JSON_ENCODE_ANY | JSON_COMPACT);
      if (!tmp)
        error(EXIT_FAILURE, 0, "Error calling json_dumps()");

      if (setxattr(file, attr, tmp, strlen(tmp) + 1, XATTR_REPLACE) != 0)
        error(EXIT_FAILURE, errno, "Error calling setxattr()");

      mem_free(tmp);
    }
  } else if (strcmp(cmd, "acquire") == 0) {
    pin_t *pin = NULL;

    if (attr) {
      ssize_t alen = 0;
      char *buf = NULL;

      alen = getxattr(file, attr, NULL, 0);
      if (alen < 0)
        error(EXIT_FAILURE, errno, "Error calling getxattr()");

      buf = mem_malloc(alen);
      if (!buf)
        error(EXIT_FAILURE, errno, "Error calling buf_new()");

      if (getxattr(file, attr, buf, alen) != (ssize_t) alen)
        error(EXIT_FAILURE, errno, "Error calling getxattr()");

      if (buf[alen - 1] != '\0')
        error(EXIT_FAILURE, errno, "Metadata not NULL terminated");

      data = json_loads(buf, 0, &jerr);
    } else {
      data = json_load_file(file, 0, &jerr);
    }

    if (!data)
      error(EXIT_FAILURE, 0, "Error parsing data");

    pin = ops_acquire_start("0", data);
    if (!pin)
      error(EXIT_FAILURE, 0, "Error calling ops_acquire_start()");

    key = ops_acquire_finish(&pin, data);
    if (!key)
      error(EXIT_FAILURE, 0, "Error calling ops_acquire_finish()");
  }
  if (!key)
    error(EXIT_FAILURE, errno, "Unable to %s key", cmd);

  switch (fmt) {
  case 'b':
    fwrite(key->buf, 1, key->len, stdout);
    break;

  case 'x':
  case 'X':
    for (size_t i = 0; i < key->len; i++)
      fprintf(stdout, fmt == 'x' ? "%02x" : "%02X", key->buf[i]);
    fprintf(stdout, "\n");
    break;
  }

  EVP_cleanup();
  return EXIT_SUCCESS;

usage:
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [-h] [-f fmt] [-x xattr] provision FILE BYTES CONF\n",
	  basename(argv[0]));
  fprintf(stderr, "%s [-h] [-f fmt] [-x xattr] acquire FILE\n",
	  basename(argv[0]));

  EVP_cleanup();
  return EXIT_FAILURE;
}
