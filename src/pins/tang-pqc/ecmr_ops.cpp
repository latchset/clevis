// vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80:
//
// Copyright (c) 2026 Red Hat, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "ecmr_ops.h"
#include "jose_wrapper.h"

namespace clevis {

JsonPtr EcmrOps::blind(const json_t* clientPub, const json_t* ephemeral)
{
    return JoseWrapper::ecmrExchange(clientPub, ephemeral);
}

JsonPtr EcmrOps::unblind(
    const json_t* response,
    const json_t* ephemeral,
    const json_t* serverPub)
{
    auto tmp = JoseWrapper::ecmrExchange(ephemeral, serverPub);
    auto repPub = JoseWrapper::publicKey(response);
    return JoseWrapper::ecmrExchange(repPub.get(), tmp.get());
}

} // namespace clevis
