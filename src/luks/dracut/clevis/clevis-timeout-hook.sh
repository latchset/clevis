#!/bin/sh
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

[ ! -f /run/clevis-online ] || exit 0

# shellcheck disable=SC2154 # $hookdir is a dracut variable
# If the network did not come online by the initqueue timeout, run the askpass
# hook from settled so the password prompt remains available as a fallback.
for askpass in "$hookdir"/initqueue/online/cryptroot-ask-*.sh; do
    [ -f "$askpass" ] || continue
    if mv -f "$askpass" "$hookdir/initqueue/settled/${askpass##*/}"; then
        : > /run/clevis-network-timeout
    fi
done
