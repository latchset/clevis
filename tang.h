/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
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

#include <jansson.h>
#include <stdbool.h>

/**
 * Validates an advertisement.
 *
 * This function ensures that the advertisment has all required attributes
 * and that it is signed by all included signing keys. It returns an array
 * of the keys inside the advertisement payload on success.
 */
json_t *
tang_validate(const json_t *jws);

/**
 * Encrypt data using the specified binding key.
 *
 * Returns a JWE along with headers required for recovery.
 */
bool
tang_bind(json_t *jwe, json_t *cek, const json_t *jwk,
          const char *url, const json_t *adv);

/**
 * Creates the recovery request from the JWE.
 *
 * DO NOT persist JWE after calling this function as it may be modified.
 *
 * Returns the recovery request.
 */
bool
tang_prepare(const json_t *jwe, const json_t *rcp, json_t **req, json_t **eph);

/**
 * Recovers the key after a recovery request.
 *
 * DO NOT persist JWE after calling this function as it may be modified.
 *
 * Returns the recovered data.
 */
json_t *
tang_recover(const json_t *jwe, const json_t *rcp,
             const json_t *eph, const json_t *rep);
