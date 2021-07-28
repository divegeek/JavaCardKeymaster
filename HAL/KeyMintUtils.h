/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <log/log.h>

#include <Certificate.h>
#include <HardwareAuthToken.h>
#include <HardwareAuthenticatorType.h>
#include <KeyFormat.h>
#include <KeyParameter.h>
#include <KeyPurpose.h>
#include <ScopedAStatus.h>
#include <SecurityLevel.h>
#include <Tag.h>

#include <keymaster/keymaster_enforcement.h>

namespace keymint::javacard {
using namespace keymaster::javacard::test;
using keymaster::javacard::test::HardwareAuthToken;
using std::vector;

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return static_cast<keymaster_tag_t>(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return static_cast<Tag>(value);
}

inline keymaster_purpose_t legacy_enum_conversion(const KeyPurpose value) {
    return static_cast<keymaster_purpose_t>(value);
}

inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return static_cast<keymaster_key_format_t>(value);
}

inline SecurityLevel legacy_enum_conversion(const keymaster_security_level_t value) {
    return static_cast<SecurityLevel>(value);
}

inline hw_authenticator_type_t legacy_enum_conversion(const HardwareAuthenticatorType value) {
    return static_cast<hw_authenticator_type_t>(value);
}

inline ScopedAStatus kmError2ScopedAStatus(const keymaster_error_t value) {
    return (value == KM_ERROR_OK ? ScopedAStatus::ok()
                                 : ScopedAStatus(static_cast<int32_t>(value)));
    //          : ScopedAStatus(AStatus_fromServiceSpecificError(static_cast<int32_t>(value))));
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

KeyParameter kmParam2Aidl(const keymaster_key_param_t& param);
vector<KeyParameter> kmParamSet2Aidl(const keymaster_key_param_set_t& set);
keymaster_key_param_set_t aidlKeyParams2Km(const vector<KeyParameter>& keyParams);

class KmParamSet : public keymaster_key_param_set_t {
  public:
    explicit KmParamSet(const vector<KeyParameter>& keyParams)
        : keymaster_key_param_set_t(aidlKeyParams2Km(keyParams)) {}

    KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
        other.length = 0;
        other.params = nullptr;
    }

    KmParamSet(const KmParamSet&) = delete;
    ~KmParamSet() { keymaster_free_param_set(this); }
};

inline vector<uint8_t> kmBlob2vector(const keymaster_key_blob_t& blob) {
    vector<uint8_t> result(blob.key_material, blob.key_material + blob.key_material_size);
    return result;
}

inline vector<uint8_t> kmBlob2vector(const keymaster_blob_t& blob) {
    vector<uint8_t> result(blob.data, blob.data + blob.data_length);
    return result;
}

inline vector<uint8_t> kmBuffer2vector(const ::keymaster::Buffer& buf) {
    vector<uint8_t> result(buf.peek_read(), buf.peek_read() + buf.available_read());
    return result;
}

inline vector<Certificate> kmCertChain2Aidl(const keymaster_cert_chain_t& cert_chain) {
    vector<Certificate> result;
    if (!cert_chain.entry_count || !cert_chain.entries) return result;

    result.resize(cert_chain.entry_count);
    for (size_t i = 0; i < cert_chain.entry_count; ++i) {
        result[i].encodedCertificate = kmBlob2vector(cert_chain.entries[i]);
    }

    return result;
}

template <typename T, typename OutIter>
inline OutIter copy_bytes_to_iterator(const T& value, OutIter dest) {
    const uint8_t* value_ptr = reinterpret_cast<const uint8_t*>(&value);
    return std::copy(value_ptr, value_ptr + sizeof(value), dest);
}

vector<uint8_t> authToken2AidlVec(const HardwareAuthToken& token);

inline void addClientAndAppData(const vector<uint8_t>& clientId, const vector<uint8_t>& appData,
                                ::keymaster::AuthorizationSet* params) {
    params->Clear();
    if (clientId.size()) {
        params->push_back(::keymaster::TAG_APPLICATION_ID, clientId.data(), clientId.size());
    }
    if (appData.size()) {
        params->push_back(::keymaster::TAG_APPLICATION_DATA, appData.data(), appData.size());
    }
}

}  // namespace keymint::javacard
