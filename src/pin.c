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

#include "pin.h"
#include "list.h"

#include <pthread.h>

#include <dlfcn.h>
#include <limits.h>
#include <string.h>

#define _STR(s) # s
#define STR(s) _STR(s)

typedef struct {
  list_t list;
  char name[];
} entry_t;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static list_t names = LIST_INIT(names);

static const entry_t *
find(const char *name)
{
  LIST_FOREACH(&names, entry_t, e, list) {
    if (strcmp(name, e->name) == 0)
      return e;
  }

  return NULL;
}

static const char *
propose(const char *name, bool iter)
{
  unsigned char i = 0;
  entry_t *tmp = NULL;

  tmp = calloc(1, offsetof(entry_t, name) + strlen(name) + 4);
  if (!tmp)
    return NULL;

  strcpy(tmp->name, name);

  pthread_mutex_lock(&mutex);

  while (iter && i < UCHAR_MAX && find(tmp->name))
    snprintf(tmp->name, strlen(name) + 3, "%s%hhu", name, ++i);

  if (find(tmp->name)) {
    free(tmp);
    tmp = NULL;
  } else {
    list_add_after(&names, &tmp->list);
  }

  pthread_mutex_unlock(&mutex);
  return tmp ? tmp->name : NULL;
}

bool
pin_name(json_t *layout)
{
  json_t *name = NULL;

  name = json_incref(json_object_get(layout, "name"));
  if (name) {
    if (!json_is_string(name))
      return false;

    if (!propose(json_string_value(name), false))
      return false;
  } else {
    name = json_object_get(layout, "type");
    if (!json_is_string(name))
      return false;

    name = json_string(propose(json_string_value(name), true));
    if (!name)
      return false;
  }

  return json_object_set_new(layout, "name", name) >= 0;
}

pin_t *
pin_load(const char *type)
{
  const char *pindir = NULL;
  char path[PATH_MAX] = {};
  pin_t *pin = NULL;
  int r;

  pindir = getenv("CLEVIS_PINDIR");
  if (!pindir)
    pindir = CLEVIS_PINDIR;

  r = snprintf(path, PATH_MAX, "%s/%s.so", pindir, type);
  if (r < (int) strlen(type) + 4 || r == PATH_MAX)
    return NULL;

  pin = malloc(sizeof(*pin));
  if (!pin)
    return NULL;

  pthread_mutex_lock(&mutex);
  pin->dll = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  pthread_mutex_unlock(&mutex);
  if (!pin->dll) {
    if (getenv("CLEVIS_DEBUG"))
      fprintf(stderr, "%s\n", dlerror());

    free(pin);
    return NULL;
  }

  pthread_mutex_lock(&mutex);
  pin->pin = dlsym(pin->dll, STR(CLEVIS_PIN));
  pthread_mutex_unlock(&mutex);
  if (!pin->pin) {
    if (getenv("CLEVIS_DEBUG"))
      fprintf(stderr, "Symbol not found in %s!\n", path);

    dlclose(pin->pin);
    free(pin);
    return NULL;
  }

  return pin;
}

void
pin_free(pin_t *pin)
{
  if (pin) {
    pthread_mutex_lock(&mutex);
    dlclose(pin->dll);
    pthread_mutex_unlock(&mutex);
  }

  free(pin);
}
