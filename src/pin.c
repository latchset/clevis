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
#include "mem.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

struct pin {
  pid_t pid;
  FILE *out;
};

pin_t *
pin_start(const char *name, const char *command, const char *branch,
          const json_t *req)
{
  const char *pindir = NULL;
  int out[2] = { -1, -1 };
  int in[2] = { -1, -1 };
  char *json = NULL;
  pin_t *pin = NULL;
  pid_t pid = -1;

  pindir = getenv("CLEVIS_PINDIR");
  if (!pindir)
    pindir = CLEVIS_PINDIR;

  if (strlen(pindir) + strlen(name) + 2 >= PATH_MAX)
    return NULL;

  json = json_dumps(req, JSON_COMPACT);
  if (!json)
    return NULL;

  if (pipe(out) != 0)
    goto error;

  if (pipe(in) != 0)
    goto error;

  pid = fork();
  if (pid < 0)
    goto error;

  if (pid == 0) {
    char path[PATH_MAX];

    dup2(out[0], STDIN_FILENO);
    dup2(in[1], STDOUT_FILENO);
    close(out[1]);
    close(in[0]);

    strcpy(path, pindir);
    strcat(path, "/");
    strcat(path, name);

    exit(execl(path, path, command, branch, NULL));
  }

  if (write(out[1], json, strlen(json)) != (ssize_t) strlen(json))
    goto error;

  pin = calloc(1, sizeof(*pin));
  if (!pin)
    goto error;
  pin->pid = pid;
  pin->out = fdopen(in[0], "r");
  if (!pin->out) {
    free(pin);
    goto error;
  }

  close(out[0]);
  close(out[1]);
  close(in[1]);
  mem_free(json);
  return pin;

error:
  if (pid >= 0) {
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
  }

  close(out[0]);
  close(out[1]);
  close(in[0]);
  close(in[1]);
  mem_free(json);
  return NULL;
}

int
pin_fd(const pin_t *pin)
{
  return pin ? fileno(pin->out) : -1;
}

void
pin_cancel(pin_t **pin)
{
  if (!pin || !*pin)
    return;

  kill((*pin)->pid, SIGTERM);
  waitpid((*pin)->pid, NULL, 0);
  fclose((*pin)->out);
  free(*pin);
  *pin = NULL;
}

json_t *
pin_finish(pin_t **pin)
{
  json_error_t err = {};
  json_t *rep = NULL;

  rep = json_loadf((*pin)->out, JSON_DECODE_ANY, &err);
  if (!rep)
    kill((*pin)->pid, SIGTERM);

  waitpid((*pin)->pid, NULL, 0);
  fclose((*pin)->out);
  free(*pin);
  *pin = NULL;
  return rep;
}
