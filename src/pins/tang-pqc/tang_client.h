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

#include "jose_types.h"

#include <string>

namespace clevis {

struct TlsConfig {
    std::string cacert;
    std::string cert;
    std::string key;
};

struct VersionInfo {
    bool tangPub = false;
    bool hybridRecovery = false;
};

struct KemRecoveryResponse {
    std::string tangEncryptedKey;
    std::string tangTransportCt;
};

class TangClient {
public:
    TangClient(const std::string& url, const TlsConfig& tls = {});

    JsonPtr fetchAdvertisement(const std::string& thp = "");
    JsonPtr fetchKemAdvertisement();
    VersionInfo fetchVersion();

    JsonPtr ecmrRecover(
        const std::string& kid, const json_t* blindedKey);

    KemRecoveryResponse kemRecover(
        const std::string& kemKid,
        const std::string& encryptedBlob,
        const std::string& transportCt);

private:
    std::string httpGet(const std::string& path);
    std::string httpPost(
        const std::string& path,
        const std::string& body,
        const std::string& contentType);

    std::string url_;
    TlsConfig tls_;
};

} // namespace clevis
