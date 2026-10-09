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

size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    try {
        auto& response = *static_cast<std::string*>(userp);
        response.append(static_cast<char*>(contents), size * nmemb);
        return size * nmemb;
    } catch (...) {
        return 0;
    }
}

CurlPtr createCurl(const std::string& url, const TlsConfig& tls)
{
    CurlPtr curl(curl_easy_init());
    if (!curl)
        throw PinError("Failed to initialize curl");

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 30L);

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
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());

    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));

    std::string response;
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl.get());

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

JsonPtr TangClient::fetchKemAdvertisement()
{
    auto body = httpGet("/adv-kem");
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
