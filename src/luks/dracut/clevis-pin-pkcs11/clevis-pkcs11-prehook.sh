#!/bin/sh
#
# Copyright (c) 2024 Red Hat, Inc.
# Author: Sergio Arroutbi <sarroutb@redhat.com>
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
if [ ! -f /run/systemd/clevis-pkcs11.pre.run ] && [ -d /run/systemd ];
then
  clevis-pkcs11-afunix-socket-unlock -l /run/systemd/clevis-pkcs11-dracut.log -f /run/systemd/clevis-pkcs11.sock -s 60 &
  echo "" > /run/systemd/clevis-pkcs11.pre.run
fi
