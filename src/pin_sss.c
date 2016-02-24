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

#include "pin_sss_alg.h"
#include "pin.h"

#include <pthread.h>
#include <semaphore.h>

typedef struct {
  clevis_acquire_f funcs;
  pthread_mutex_t mutex;
  size_t threshold;
  list_t pending;
  list_t success;
  list_t failure;
  sem_t sem;
  bool dead;
} acquire_t;

typedef struct {
  sss_point_t point;
  acquire_t *acq;
  json_t *data;
  pin_t *pin;
} acquire_pin_t;

static bool
get_int(const json_t *obj, const char *name, json_int_t min, size_t *out)
{
  const json_t *j = NULL;
  json_int_t i = 0;

  j = json_object_get(obj, name);
  if (!json_is_number(j))
    return false;

  i = json_integer_value(j);
  if (i < min)
    return false;

  *out = i;
  return true;
}

static json_t *
provision_pin(const clevis_provision_f *funcs, const json_t *lay,
	      const clevis_buf_t *y)
{
  const char *type = NULL;
  json_t *d = NULL;
  json_t *l = NULL;
  pin_t *pin = NULL;

  if (!json_is_object(lay) || !json_is_string(json_object_get(lay, "type")))
    return NULL;

  type = json_string_value(json_object_get(lay, "type"));
  if (!type)
    return NULL;

  l = json_deep_copy(lay);
  if (!l)
    return NULL;

  if (!pin_name(l))
    goto error;

  pin = pin_load(type);
  if (!pin)
    goto error;

  d = pin->pin->provision(funcs, l, y);
  pin_free(pin);
  if (!json_is_object(d))
    goto error;

  if (json_object_set(d, "type", json_object_get(l, "type")) < 0)
    goto error;

  if (json_object_set(d, "name", json_object_get(l, "name")) < 0)
    goto error;

  json_decref(l);
  return d;

error:
  json_decref(d);
  json_decref(l);
  return NULL;
}

static json_t *
provision(const clevis_provision_f *funcs,
          const json_t *cfg, const clevis_buf_t *key)
{
  clevis_buf_t *prime = NULL;
  const json_t *cfgs = NULL;
  clevis_buf_t *k = NULL;
  size_t threshold = 0;
  json_t *data = NULL;
  json_t *pins = NULL;
  BN_CTX *ctx = NULL;
  sss_t *sss = NULL;

  if (!get_int(cfg, "threshold", 1, &threshold))
    return NULL;

  cfgs = json_object_get(cfg, "pins");
  if (!json_is_array(cfgs) || json_array_size(cfgs) < threshold) {
    fprintf(stderr, "Number of pins must be > threshold!\n");
    return NULL;
  }

  ctx = BN_CTX_new();
  if (!ctx)
    goto error;

  sss = sss_generate(key->len, threshold);
  if (!sss)
    goto error;

  data = json_object();
  if (!data)
    goto error;

  if (json_object_set(data, "threshold", json_object_get(cfg, "threshold")) < 0)
    goto error;

  prime = sss_p(sss);
  if (!prime)
    goto error;
  if (json_object_set_new(data, "prime", clevis_buf_encode(prime)) < 0) {
    clevis_buf_free(prime);
    goto error;
  }
  clevis_buf_free(prime);

  pins = json_array();
  if (json_object_set_new(data, "pins", pins) < 0)
    goto error;

  for (unsigned long i = 0; i < json_array_size(cfgs); i++) {
    const json_t *lay = NULL;
    clevis_buf_t *y = NULL;
    json_t *pin = NULL;

    lay = json_array_get(cfgs, i);
    if (!json_is_object(lay)) {
      fprintf(stderr, "Pin config must be an object!\n");
      goto error;
    }

    pin = json_object();
    if (json_array_append_new(pins, pin) < 0)
      goto error;

    if (json_object_set_new(pin, "x", json_integer(i + 1)) < 0)
      goto error;

    y = sss_y(sss, i + 1, ctx);
    if (!y)
      goto error;

    if (json_object_set_new(pin, "data", provision_pin(funcs, lay, y)) < 0) {
      clevis_buf_free(y);
      goto error;
    }

    clevis_buf_free(y);
  }

  k = sss_y(sss, 0, ctx);
  if (!k)
    goto error;

  if (json_object_set_new(data, "ct", funcs->encrypt(k, key)) < 0)
    goto error;

  clevis_buf_free(k);
  BN_CTX_free(ctx);
  sss_free(sss);
  return data;

error:
  clevis_buf_free(k);
  json_decref(data);
  BN_CTX_free(ctx);
  sss_free(sss);
  return NULL;
}

static void
acqp_free(acquire_pin_t *acqp)
{
  if (!acqp)
    return;

  clevis_buf_free(acqp->point.y);
  json_decref(acqp->data);
  pin_free(acqp->pin);
  free(acqp);
}

static acquire_pin_t *
acqp_new(acquire_t *acq, const json_t *pin)
{
  acquire_pin_t *acqp = NULL;
  const json_t *type = NULL;

  acqp = calloc(1, sizeof(*acqp));
  if (!acqp)
    return NULL;

  acqp->acq = acq;
  acqp->point.list = LIST_INIT(acqp->point.list);

  if (!get_int(pin, "x", 1, &acqp->point.x))
    goto error;

  acqp->data = json_deep_copy(json_object_get(pin, "data"));
  if (!acqp->data)
    goto error;

  type = json_object_get(acqp->data, "type");
  if (!json_is_string(type))
    goto error;

  acqp->pin = pin_load(json_string_value(type));
  if (!acqp->pin)
    goto error;

  return acqp;

error:
  free(acqp);
  return NULL;
}

static void
acq_free(acquire_t *acq)
{
  if (!acq)
    return;

  LIST_FOREACH(&acq->failure, acquire_pin_t, acqp, point.list) {
    list_pop(&acqp->point.list);
    acqp_free(acqp);
  }

  LIST_FOREACH(&acq->success, acquire_pin_t, acqp, point.list) {
    list_pop(&acqp->point.list);
    acqp_free(acqp);
  }

  pthread_mutex_destroy(&acq->mutex);
  sem_destroy(&acq->sem);
  free(acq);
}

static acquire_t *
acq_new(clevis_acquire_f funcs, const json_t *data)
{
  acquire_t *acq = NULL;

  acq = calloc(1, sizeof(*acq));
  if (!acq)
    return NULL;

  acq->pending = LIST_INIT(acq->pending);
  acq->success = LIST_INIT(acq->success);
  acq->failure = LIST_INIT(acq->failure);
  acq->funcs = funcs;

  if (pthread_mutex_init(&acq->mutex, NULL) != 0)
    goto error;

  if (sem_init(&acq->sem, 0, 0) != 0)
    goto error;

  if (!get_int(data, "threshold", 1, &acq->threshold))
    goto error;

  return acq;

error:
  acq_free(acq);
  return NULL;
}

static void *
acquire_pin(void *misc)
{
  acquire_pin_t *acqp = misc;
  bool freeacq = false;

  acqp->point.y = acqp->pin->pin->acquire(&acqp->acq->funcs, acqp->data);

  pthread_mutex_lock(&acqp->acq->mutex);

  list_add_after(acqp->point.y
		   ? &acqp->acq->success
		   : &acqp->acq->failure,
                 list_pop(&acqp->point.list));

  freeacq = LIST_EMPTY(&acqp->acq->pending) && acqp->acq->dead;
  sem_post(&acqp->acq->sem);

  pthread_mutex_unlock(&acqp->acq->mutex);

  if (freeacq)
    acq_free(acqp->acq);

  return NULL;
}

static bool
acquire_pin_start(acquire_pin_t *acqp)
{
  pthread_attr_t attr;
  pthread_t thread;
  bool ret = false;

  if (pthread_attr_init(&attr) == 0) {
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0)
      ret = pthread_create(&thread, &attr, acquire_pin, acqp) == 0;
    pthread_attr_destroy(&attr);
  }

  return ret;
}

static clevis_buf_t *
acquire(const clevis_acquire_f *funcs, const json_t *data)
{
  clevis_buf_t *prime = NULL;
  const json_t *pins = NULL;
  clevis_buf_t *key = NULL;
  acquire_t *acq = NULL;
  BN_CTX *ctx = NULL;

  acq = acq_new(*funcs, data);
  if (!acq)
    return NULL;

  ctx = BN_CTX_new();
  if (!ctx)
    goto egress;

  prime = clevis_buf_decode(json_object_get(data, "prime"));
  if (!prime)
    goto egress;

  pins = json_object_get(data, "pins");
  if (!json_is_array(pins))
    goto egress;

  for (size_t i = 0; i < json_array_size(pins); i++) {
    acquire_pin_t *acqp = NULL;

    acqp = acqp_new(acq, json_array_get(pins, i));
    if (!acqp)
      goto egress;

    list_add_after(&acq->pending, &acqp->point.list);
  }

  pthread_mutex_lock(&acq->mutex);

  LIST_FOREACH(&acq->pending, acquire_pin_t, acqp, point.list) {
    if (!acquire_pin_start(acqp)) {
      pthread_mutex_unlock(&acq->mutex);
      goto egress;
    }
  }

  pthread_mutex_unlock(&acq->mutex);

  for (size_t done = 0; done < json_array_size(pins); done++) {
    size_t success = 0;

    sem_wait(&acq->sem);
    pthread_mutex_lock(&acq->mutex);

    LIST_FOREACH(&acq->success, acquire_pin_t, acqp, point.list)
      success++;

    if (success >= acq->threshold) {
      key = sss_recover(prime, &acq->success, ctx);
      pthread_mutex_unlock(&acq->mutex);
      break;
    }

    pthread_mutex_unlock(&acq->mutex);
  }

egress:
  pthread_mutex_lock(&acq->mutex);

  LIST_FOREACH(&acq->failure, acquire_pin_t, acqp, point.list) {
    list_pop(&acqp->point.list);
    acqp_free(acqp);
  }

  LIST_FOREACH(&acq->success, acquire_pin_t, acqp, point.list) {
    list_pop(&acqp->point.list);
    acqp_free(acqp);
  }

  acq->dead = !LIST_EMPTY(&acq->pending);
  pthread_mutex_unlock(&acq->mutex);

  if (!acq->dead)
    acq_free(acq);

  if (key) {
    clevis_decrypt_result_t result =
      funcs->decrypt(key, json_object_get(data, "ct"));
    clevis_buf_free(key);
    key = result.pt;
  }

  clevis_buf_free(prime);
  BN_CTX_free(ctx);
  return key;
}

clevis_pin_f CLEVIS_PIN = {
  .provision = provision,
  .acquire = acquire
};
