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

#include "sss_algo.h"
#include "../mem.h"
#include "../ops.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <poll.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define error(rv, err, ...) { \
  fprintf(stderr, __VA_ARGS__); \
  if (err != 0) \
    fprintf(stderr, ":%s", strerror(err)); \
  fprintf(stderr, "\n"); \
  return rv; \
}

static inline BN_CTX *
openssl_init(void)
{
  uint8_t buf[128];
  FILE *f = NULL;
  size_t r = 0;

  OpenSSL_add_all_algorithms();

  f = fopen("/dev/random", "r");
  if (!f)
    error(NULL, errno, "Unable to open /dev/urandom");

  r = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  if (r != sizeof(buf))
    error(NULL, errno, "Unable to read /dev/urandom");

  RAND_seed(buf, sizeof(buf));
  return BN_CTX_new();
}

static json_t *
rep_prepare(const sss_t *sss, json_t *thr, BN_CTX *ctx)
{
  json_auto_t *rep = NULL;

  rep = json_object();
  if (!json_is_object(rep))
    return NULL;

  if (json_object_put_new(rep, "key", sss_k(sss)) < 0)
    return NULL;

  if (json_object_put_new(rep, "data.prime", sss_p(sss)) < 0)
    return NULL;

  if (json_object_put_new(rep, "data.threshold", json_incref(thr)) < 0)
    return NULL;

  if (json_object_put_new(rep, "data.pins", json_array()) < 0)
    return NULL;

  return json_incref(rep);
}

static json_t *
provision(const char *branch, BN_CTX *ctx, json_t *req)
{
  json_auto_t *rep = NULL;
  sss_auto_t *sss = NULL;
  json_t *cfgs = NULL;
  json_t *thr = NULL;

  thr = json_object_fetch(req, "cfg.threshold");
  if (!json_is_integer(thr))
    error(NULL, 0, "Threshold must be an integer: %s", branch);

  cfgs = json_object_fetch(req, "cfg.pins");
  if (!json_is_array(cfgs))
    error(NULL, 0, "Pins must be an array: %s", branch);

  sss = sss_generate(json_object_get(req, "size"), thr);
  if (!sss)
    error(NULL, 0, "Invalid SSS parameters: %s", branch);

  rep = rep_prepare(sss, thr, ctx);
  if (!json_is_object(rep))
    error(NULL, 0, "Error generating reply: %s", branch);

  for (unsigned long i = 0; i < json_array_size(cfgs); i++) {
    char br[strlen(branch) + 128];
    buf_auto_t *key = NULL;
    json_t *data = NULL;
    json_t *cfg = NULL;
    int r;

    r = snprintf(br, sizeof(br), "%s.%lu", branch, i);
    if (r < 0 || r == (int) sizeof(br))
      error(NULL, 0, "Error forming branch: %s", branch);

    cfg = json_array_get(cfgs, i);
    if (!json_is_object(cfg))
      error(NULL, 0, "Pin config must be an object: %s", br);

    key = sss_y(sss, i + 1, ctx);
    if (!key)
      error(NULL, 0, "Unable to generate SSS key: %s", br);

    data = ops_provision(br, cfg, key);
    if (!data)
      error(NULL, 0, "Error calling ops_provision_start(): %s", br);

    if (json_array_append_new(json_object_fetch(rep, "data.pins"), data) < 0)
      error(NULL, 0, "Error setting reply: %s.%lu", branch, i);
  }

  return json_incref(rep);
}

static json_t *
acquire(const char *branch, BN_CTX *ctx, json_t *req)
{
  json_auto_t *points = NULL;
  json_t *datas = NULL;
  json_t *thr = NULL;
  json_t *p = NULL;
  size_t ndatas;

  points = json_array();
  if (!json_is_array(points))
    return NULL;

  datas = json_object_get(req, "pins");
  if (!json_is_array(datas))
    error(NULL, 0, "Pins must be an array: %s", branch);
  ndatas = json_array_size(datas);

  thr = json_object_get(req, "threshold");
  if (!json_is_integer(thr))
    error(NULL, 0, "Threshold must be an integer: %s", branch);

  p = json_object_get(req, "prime");
  if (!json_is_string(p) && !json_is_integer(p))
    error(NULL, 0, "Prime must be binary or an integer: %s", branch);

  pin_t *pins[ndatas];
  memset(pins, 0, sizeof(pins));

  for (size_t i = 0; i < ndatas; i++) {
    char br[strlen(branch) + 128];
    int r;

    r = snprintf(br, sizeof(br), "%s.%lu", branch, i);
    if (r < 0 || r == (int) sizeof(br))
      error(NULL, 0, "Error forming branch: %s", branch);

    pins[i] = ops_acquire_start(br, json_array_get(datas, i));
    if (!pins[i]) {
      for (ssize_t j = i - 1; j >= 0; j--)
	pin_cancel(&pins[i]);
      error(NULL, 0, "Error starting branch: %s", branch);
    }
  }

  while (json_array_size(points) < (size_t) json_integer_value(thr)) {
    struct pollfd pfds[ndatas];
    nfds_t cnt = 0;
    int r = 0;

    for (size_t i = 0; i < json_array_size(datas); i++) {
      pfds[cnt].fd = pin_fd(pins[i]);
      if (pfds[cnt].fd >= 0)
      	pfds[cnt++].events = POLLIN | POLLPRI | POLLHUP;
    }

    r = poll(pfds, cnt, -1);
    if (r < 0) {
      for (size_t i = 0; i < ndatas; i++)
        pin_cancel(&pins[i]);
      error(NULL, errno, "Error during poll()");
    }

    for (int i = 0; i < r; i++) {
      for (uint64_t j = 0; j < ndatas; j++) {
	json_auto_t *point = NULL;
	buf_auto_t *key = NULL;

	if (pfds[i].fd != pin_fd(pins[j]))
	  continue;

	key = ops_acquire_finish(&pins[j], json_array_get(datas, j));
	if (!key) {
          fprintf(stderr, "Branch %s.%lu failed\n", branch, j);
	  continue;
	}

        point = json_array();
	if (!json_is_array(point)
	    || json_array_append_new(point, json_integer(j)) < 0
	    || json_array_append_new(point, json_binary(key)) < 0
	    || json_array_append(points, point)) {
          for (size_t k = 0; k < ndatas; k++)
            pin_cancel(&pins[k]);
	  error(NULL, 0, "Error creating point: %s.%lu", branch, j);
	}

	break;
      }
    }
  }

  for (size_t i = 0; i < ndatas; i++)
    pin_cancel(&pins[i]);

  return sss_recover(p, points, ctx);
}

int
main(int argc, char *argv[])
{
  const char *command = NULL;
  const char *branch = NULL;
  json_auto_t *req = NULL;
  json_auto_t *rep = NULL;
  json_error_t err = {};
  BN_CTX *ctx = NULL;

  json_set_alloc_funcs(mem_malloc, mem_free);
  ctx = openssl_init();
  if (!ctx)
    error(EXIT_FAILURE, 0, "Unable to initialize OpenSSL");

  if (argc != 3)
    goto usage;

  command = argv[1];
  branch = argv[2];

  req = json_loadf(stdin, 0, &err);
  if (!json_is_object(req))
    error(EXIT_FAILURE, 0, "Input must be a JSON object: %s", branch);

  if (strcmp(command, "provision") == 0) {
    rep = provision(branch, ctx, req);
  } else if (strcmp(command, "acquire") == 0) {
    rep = acquire(branch, ctx, req);
  } else {
    error(EXIT_FAILURE, 0, "Command must be provision or acquire: %s", branch);
  }
  if (!rep)
    return EXIT_FAILURE; /* Error message already printed. */

  if (json_dumpf(rep, stdout, JSON_ENCODE_ANY) < 0)
    error(EXIT_FAILURE, 0, "Error writing output: %s", branch);

  BN_CTX_free(ctx);
  EVP_cleanup();
  return EXIT_SUCCESS;

usage:
  fprintf(stderr, "Usage: %s [-h] [-d pindir] COMMAND BRANCH\n", argv[0]);
  return EXIT_FAILURE;
}
