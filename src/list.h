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

#pragma once

#include <stddef.h>

#define LIST_UNWRAP(p, t, m) ({ (t *) ((void *) (p) - offsetof(t, m)); })

typedef struct list list_t;

struct list {
    list_t *prev;
    list_t *next;
};

#define LIST(name) list_t name = TANG_LIST_INIT(name)
#define LIST_INIT(name) (list_t) { &(name), &(name) }
#define LIST_ITEM(item, type, member) ({ \
    (type *) ((unsigned char *) (item) - offsetof(type, member)); \
})

#define LIST_EMPTY(list) ((list)->prev == (list) && (list)->next == (list))

#define LIST_FOREACH(list, type, name, member) \
    for (type *__l ## name = LIST_ITEM(list, type, member), \
              *name  = LIST_ITEM(__l ## name->member.next, type, member), \
              *__n ## name = LIST_ITEM(name->member.next, type, member); \
               name != __l ## name; name = __n ## name, \
              __n ## name  = LIST_ITEM(name->member.next, type, member))

void
list_add_after(list_t *list, list_t *item);

list_t *
list_pop(list_t *item);
