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

inline void validateEcCurve(const char* crv)
{
    if (!crv)
        throw PinError("EC curve is null");
    if (std::strcmp(crv, "P-256") != 0
        && std::strcmp(crv, "P-384") != 0
        && std::strcmp(crv, "P-521") != 0)
        throw PinError(
            std::string("Unsupported EC curve: ") + crv);
}

inline void validateBase64Url(
    const std::string& value, const char* fieldName)
{
    for (auto ch : value) {
        bool ok = (ch >= 'A' && ch <= 'Z')
               || (ch >= 'a' && ch <= 'z')
               || (ch >= '0' && ch <= '9')
               || ch == '-' || ch == '_';
        if (!ok)
            throw PinError(
                std::string(fieldName)
                + " contains invalid characters");
    }
}

class CleansedString : public std::string {
public:
    using std::string::string;

    CleansedString(std::string&& s) noexcept
        : std::string(std::move(s)) {}

    CleansedString(const CleansedString&) = delete;
    CleansedString& operator=(const CleansedString&) = delete;

    CleansedString(CleansedString&& o) noexcept
        : std::string(std::move(o)) {}
    CleansedString& operator=(CleansedString&& o) noexcept
    {
        std::string::operator=(std::move(o));
        return *this;
    }

    ~CleansedString() noexcept
    {
        if (!empty())
            OPENSSL_cleanse(data(), size());
    }
};

template<typename T>
class CleansedVector : public std::vector<T> {
public:
    using std::vector<T>::vector;

    CleansedVector(std::vector<T>&& v) noexcept
        : std::vector<T>(std::move(v)) {}

    CleansedVector(const CleansedVector&) = delete;
    CleansedVector& operator=(const CleansedVector&) = delete;

    CleansedVector(CleansedVector&& o) noexcept
        : std::vector<T>(std::move(o)) {}
    CleansedVector& operator=(CleansedVector&& o) noexcept
    {
        std::vector<T>::operator=(std::move(o));
        return *this;
    }

    ~CleansedVector() noexcept
    {
        if (!this->empty())
            OPENSSL_cleanse(
                this->data(), this->size() * sizeof(T));
    }
};

inline void cleanseJsonSecrets(json_t* j) noexcept
{
    if (!j)
        return;

    if (json_is_string(j)) {
        auto s = json_string_value(j);
        if (s)
            OPENSSL_cleanse(
                const_cast<char*>(s), std::strlen(s));
        return;
    }

    if (json_is_object(j)) {
        const char* key;
        json_t* value;
        json_object_foreach(j, key, value)
            cleanseJsonSecrets(value);
        return;
    }

    if (json_is_array(j)) {
        size_t idx;
        json_t* value;
        json_array_foreach(j, idx, value)
            cleanseJsonSecrets(value);
    }
}

struct CleansedJsonDeleter {
    void operator()(json_t* j) const noexcept
    {
        cleanseJsonSecrets(j);
        if (j)
            json_decref(j);
    }
};

using CleansedJsonPtr = std::unique_ptr<json_t, CleansedJsonDeleter>;

inline CleansedJsonPtr makeCleansedJsonPtr(json_t* j)
{
    return CleansedJsonPtr(j);
}

} // namespace clevis
