#!/bin/sh
#
# Copyright (c) 2026 Oldřich Jedlička
#
# Author: Oldřich Jedlička <oldium.pro@gmail.com>
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

# Replace zfs by the wrapper atomically, keeping the original hard linked
# as zfs.clevis-orig
zfs="$(command -v zfs)" && zfs="$(readlink -f "${zfs}")" \
    && [ ! -e "${zfs}.clevis-orig" ] \
    && cp /bin/clevis-zfs-wrapper "${zfs}.clevis-new" \
    && ln "${zfs}" "${zfs}.clevis-orig" \
    && mv -f "${zfs}.clevis-new" "${zfs}"
unset zfs
