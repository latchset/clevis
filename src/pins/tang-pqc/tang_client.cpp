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

#include "tang_client.h"
#include "jose_wrapper.h"

#include <curl/curl.h>

#include <cctype>
#include <stdexcept>

namespace clevis {

namespace {

struct CurlDeleter {
    void operator()(CURL* c) const noexcept { curl_easy_cleanup(c); }
};

using CurlPtr = std::unique_ptr<CURL, CurlDeleter>;

struct SlistDeleter {
    void operator()(curl_slist* s) const noexcept
    {
        curl_slist_free_all(s);
    }
};

using SlistPtr = std::unique_ptr<curl_slist, SlistDeleter>;

constexpr size_t MAX_RESPONSE_SIZE = 1 << 20;

size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    try {
        if (size != 0 && nmemb > SIZE_MAX / size)
            return 0;
        auto totalBytes = size * nmemb;
        auto& response = *static_cast<std::string*>(userp);
        if (response.size() + totalBytes > MAX_RESPONSE_SIZE)
            return 0;
        response.append(static_cast<char*>(contents), totalBytes);
        return totalBytes;
    } catch (...) {
        return 0;
    }
}

// Returns a short printable excerpt of the server-provided error body
// so failures carry actionable diagnostics. The body is untrusted
// server input, so it is truncated and stripped of non-printable
// characters before being embedded in the error message.
std::string responseExcerpt(const std::string& body)
{
    constexpr size_t MAX_EXCERPT = 128;
    std::string excerpt;
    for (auto ch : body) {
        if (excerpt.size() >= MAX_EXCERPT)
            break;
        if (std::isprint(static_cast<unsigned char>(ch)))
            excerpt += ch;
    }
    return excerpt;
}

[[noreturn]] void throwHttpResponseError(
    const char* method,
    const std::string& path,
    long code,
    const std::string& body)
{
    if (code == 400) {
        // The hardened tang server answers HTTP 400 when the request
        // violates the protocol: an unknown or invalid 'crit' entry
        // (e.g. critting the standard 'kid' header, RFC 7515 section
        // 4.1.11) or a suite/kem_kid/alg disagreement on /rec-kem.
        // Surface it as a distinct protocol mismatch, not a transient
        // error to be retried.
        auto msg =
            std::string("Tang rejected the request with HTTP 400 on ")
            + method + " " + path
            + ": protocol mismatch (invalid 'crit' extension"
              " parameters or suite/kem_kid/alg disagreement; possible"
              " downgrade attempt or stale advertisement)";
        auto excerpt = responseExcerpt(body);
        if (!excerpt.empty())
            msg += " [server said: " + excerpt + "]";
        throw PinError(msg);
    }

    throw PinError("HTTP " + std::string(method) + " failed: " + path
                   + " (HTTP " + std::to_string(code) + ")");
}

CurlPtr createCurl(const std::string& url, const TlsConfig& tls)
{
    CurlPtr curl(curl_easy_init());
    if (!curl)
        throw PinError("Failed to initialize curl");

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    // HTTP status codes are inspected manually after the transfer so
    // that error responses (e.g. 400 from /rec-kem) can be reported
    // with their status code and body instead of a generic failure.
    curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 30L);

    curl_easy_setopt(curl.get(), CURLOPT_MAXFILESIZE_LARGE,
                     static_cast<curl_off_t>(MAX_RESPONSE_SIZE));

#if CURL_AT_LEAST_VERSION(7, 85, 0)
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS,
                     CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif

    if (!tls.cacert.empty())
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO,
                         tls.cacert.c_str());
    if (!tls.cert.empty())
        curl_easy_setopt(curl.get(), CURLOPT_SSLCERT,
                         tls.cert.c_str());
    if (!tls.key.empty())
        curl_easy_setopt(curl.get(), CURLOPT_SSLKEY,
                         tls.key.c_str());

    return curl;
}

} // anonymous namespace

TangClient::TangClient(const std::string& url, const TlsConfig& tls)
    : url_(url), tls_(tls)
{
}

std::string TangClient::httpGet(const std::string& path)
{
    std::string fullUrl = url_ + path;
    auto curl = createCurl(fullUrl, tls_);

    std::string response;
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl.get());

    long code = 0;
    if (res == CURLE_OK
        && curl_easy_getinfo(
               curl.get(), CURLINFO_RESPONSE_CODE, &code) == CURLE_OK
        && code >= 400)
        throwHttpResponseError("GET", path, code, response);

    if (res != CURLE_OK)
        throw PinError("HTTP GET failed: " + std::string(path)
                       + " (" + curl_easy_strerror(res) + ")");

    return response;
}

std::string TangClient::httpPost(
    const std::string& path,
    const std::string& body,
    const std::string& contentType)
{
    std::string fullUrl = url_ + path;
    auto curl = createCurl(fullUrl, tls_);

    std::string ctHeader = "Content-Type: " + contentType;
    SlistPtr headers(curl_slist_append(nullptr, ctHeader.c_str()));
    if (!headers)
        throw PinError("Failed to allocate HTTP header list");
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());

    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));

    std::string response;
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl.get());

    long code = 0;
    if (res == CURLE_OK
        && curl_easy_getinfo(
               curl.get(), CURLINFO_RESPONSE_CODE, &code) == CURLE_OK
        && code >= 400)
        throwHttpResponseError("POST", path, code, response);

    if (res != CURLE_OK)
        throw PinError("HTTP POST failed: " + std::string(path)
                       + " (" + curl_easy_strerror(res) + ")");

    return response;
}

JsonPtr TangClient::fetchAdvertisement(const std::string& thp)
{
    std::string path = "/adv";
    if (!thp.empty())
        path += "/" + thp;

    auto body = httpGet(path);
    return jsonParse(body);
}

JsonPtr TangClient::fetchKemAdvertisement(const std::string& alg)
{
    std::string path = "/adv-kem";
    if (!alg.empty())
        path += "?alg=" + alg;
    auto body = httpGet(path);
    return jsonParse(body);
}

JsonPtr TangClient::fetchKemKeyByThumbprint(const std::string& kemKid)
{
    auto body = httpGet("/adv-kem/" + kemKid);
    return jsonParse(body);
}

VersionInfo TangClient::fetchVersion()
{
    VersionInfo info;
    try {
        auto body = httpGet("/version");
        auto json = jsonParse(body);

        auto features = json_object_get(json.get(), "features");
        if (!features)
            return info;

        auto tangPub = json_object_get(features, "tang_pub");
        if (tangPub && json_is_true(tangPub))
            info.tangPub = true;

        auto hybrid = json_object_get(features, "hybrid_recovery");
        if (hybrid && json_is_true(hybrid))
            info.hybridRecovery = true;
    } catch (...) {
        // Version endpoint is optional
    }
    return info;
}

JsonPtr TangClient::ecmrRecover(
    const std::string& kid, const json_t* blindedKey)
{
    auto body = jsonDump(blindedKey, JSON_SORT_KEYS | JSON_COMPACT);
    auto response = httpPost(
        "/rec/" + kid, body.get(), "application/jwk+json");
    return jsonParse(response);
}

KemRecoveryResponse TangClient::kemRecover(
    const std::string& kemKid,
    const std::string& encryptedBlob,
    const std::string& transportCt)
{
    auto reqJson = makeJsonPtr(json_pack(
        "{s:s, s:s}",
        "clevis_encrypted_blob", encryptedBlob.c_str(),
        "clevis_transport_ct", transportCt.c_str()));

    auto body = jsonDump(reqJson.get());
    auto response = httpPost(
        "/rec-kem/" + kemKid, body.get(), "application/json");

    auto respJson = jsonParse(response);

    auto tangEncKey = json_string_value(
        json_object_get(respJson.get(), "tang_encrypted_key"));
    auto tangTransCt = json_string_value(
        json_object_get(respJson.get(), "tang_transport_ct"));

    if (!tangEncKey || !tangTransCt)
        throw PinError("Invalid KEM recovery response from Tang");

    return {std::string(tangEncKey), std::string(tangTransCt)};
}

} // namespace clevis
