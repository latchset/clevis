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

#include "pwd.h"
#include "list.h"

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include <semaphore.h>

struct thread {
  pthread_t thread;
  sem_t sem;
};

typedef struct {
  list_t list;
  const clevis_buf_t *key;
  struct thread *thread;
  const bool local;
  bool quit;
  sem_t sem;
} req_t;

static pthread_mutex_t rmutex = PTHREAD_MUTEX_INITIALIZER;
static list_t reqs = LIST_INIT(reqs);

static void
thread_func(struct thread *thread)
{
  for (bool empty = false; !empty; ) {
    clevis_buf_t *key = NULL;
    char *pwd = NULL;
    size_t cnt = 0;

    /* FIXME: Replace this with systemd's askpass. */
    pwd = getpass("Password: ");
    if (!pwd)
      continue;

    key = clevis_buf_make(strlen(pwd), (uint8_t *) pwd);
    if (!key)
      continue;

    pthread_mutex_lock(&rmutex);

    /* Process local verifiers first, in parallel. */
    cnt = 0;
    LIST_FOREACH(&reqs, req_t, i, list) {
      if (!i->local)
	continue;

      i->thread = thread;
      i->key = key;
      sem_post(&i->sem);
      cnt++;
    }

    for (; cnt > 0; cnt--)
      sem_wait(&thread->sem);

    cnt = 0;
    LIST_FOREACH(&reqs, req_t, i, list) {
      if (!i->local)
	continue;

      i->thread = NULL;
      i->key = NULL;
      if (i->quit) {
	list_pop(&i->list);
	if (LIST_EMPTY(&reqs))
	  i->thread = thread;
	sem_post(&i->sem);
	cnt++;
      }
    }

    /* If no local verifier succeeded, process remote verifiers, in serial. */
    if (cnt == 0) {
      LIST_FOREACH(&reqs, req_t, i, list) {
	if (i->local)
	  continue;

	i->thread = thread;
	i->key = key;
	sem_post(&i->sem);
	sem_wait(&thread->sem);
	i->thread = NULL;
	i->key = NULL;

	if (i->quit) {
	  list_pop(&i->list);
	  if (LIST_EMPTY(&reqs))
	    i->thread = thread;
	  sem_post(&i->sem);
	  break;
	}
      }
    }

    empty = LIST_EMPTY(&reqs);
    pthread_mutex_unlock(&rmutex);
    clevis_buf_free(key);
  }
}

static bool
thread_new(void)
{
  struct thread *thr = NULL;

  thr = malloc(sizeof(struct thread));
  if (!thr)
    return false;

  if (sem_init(&thr->sem, 0, 0) != 0) {
    free(thr);
    return false;
  }

  if (pthread_create(&thr->thread, NULL, (void *(*)(void *)) thread_func,
		     thr) != 0) {
    sem_destroy(&thr->sem);
    free(thr);
    return false;
  }

  return true;
}

static void
thread_free(struct thread *thr)
{
  if (!thr)
    return;

  pthread_join(thr->thread, NULL);
  sem_destroy(&thr->sem);
  free(thr);
}

bool
pwd(bool lcl, clevis_pwd_vfy *vfy, clevis_pwd_t *misc)
{
  req_t i = { .local = lcl };

  i.list = LIST_INIT(i.list);
  if (sem_init(&i.sem, 0, 0) != 0)
    return false;

  pthread_mutex_lock(&rmutex);
  list_add_after(&reqs, &i.list);
  if (reqs.next->next == &reqs) { // List has one entry.
    if (!thread_new()) {
      list_pop(&i.list);
      pthread_mutex_unlock(&rmutex);
      sem_destroy(&i.sem);
      return false;
    }
  }
  pthread_mutex_unlock(&rmutex);

  while (true) {
    sem_wait(&i.sem);

    if (i.quit)
      break;

    i.quit = vfy(i.key, misc);
    sem_post(&i.thread->sem);
  }

  thread_free(i.thread);
  sem_destroy(&i.sem);
  return true;
}
