#!/bin/bash
# vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80:
#
# Copyright (c) 2016 Red Hat, Inc.
# Author: Harald Hoyer <harald@redhat.com>
# Author: Nathaniel McCallum <npmccallum@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

UUID=cb6e8904-81ff-40da-a84a-07ab9ab5715e

shopt -s nullglob

for question in /run/systemd/ask-password/ask.*; do
    d=
    s=

    while read line; do
        case "$line" in
            Id=cryptsetup:*) d="${line##Id=cryptsetup:}";;
            Socket=*) s="${line##Socket=}";;
        esac
    done < "$question"

    [ -z "$d" -o -z "$s" ] && continue

    luksmeta show -d "$d" | while read -r -a row; do
        [ "${row[1]}" != "active" ] && continue
        [ "${row[2]}" != "$UUID" ] && continue
        n=${row[0]}

        if pt="`luksmeta load -d $d -s $n -u $UUID | clevis decrypt`"; then
            echo -n "+$pt" | nc -U -u --send-only "$s"
            break;
        fi
    done
done
