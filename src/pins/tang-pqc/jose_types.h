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

#pragma once

#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include <jansson.h>
#include <openssl/crypto.h>
}

namespace clevis {

struct JsonDeleter {
    void operator()(json_t* j) const noexcept
    {
        if (j)
            json_decref(j);
    }
};

struct FreeDeleter {
    void operator()(void* p) const noexcept
    {
        std::free(p);
    }
};

using JsonPtr = std::unique_ptr<json_t, JsonDeleter>;
using CStringPtr = std::unique_ptr<char, FreeDeleter>;
using BufferPtr = std::unique_ptr<void, FreeDeleter>;

inline JsonPtr makeJsonPtr(json_t* j)
{
    return JsonPtr(j);
}

inline JsonPtr jsonDeepCopy(const json_t* j)
{
    return makeJsonPtr(json_deep_copy(j));
}

inline JsonPtr jsonParse(const std::string& str)
{
    auto j = json_loads(str.c_str(), 0, nullptr);
    if (!j)
        throw std::runtime_error("Failed to parse JSON");
    return makeJsonPtr(j);
}

inline CStringPtr jsonDump(const json_t* j, int flags = JSON_COMPACT)
{
    auto s = json_dumps(j, flags);
    if (!s)
        throw std::runtime_error("Failed to serialize JSON");
    return CStringPtr(s);
}

class PinError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

} // namespace clevis
