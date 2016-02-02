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

#include "list.h"
#include <stddef.h>

void
list_add_after(list_t *list, list_t *item)
{
    item->next = list->next;
    item->prev = list;
    list->next->prev = item;
    list->next = item;
}

list_t *
list_pop(list_t *item)
{
    if (item == NULL)
        return NULL;

    item->prev->next = item->next;
    item->next->prev = item->prev;
    return item;
}
