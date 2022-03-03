/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <vector>

namespace aidl::android::hardware::security::keymint::km_utils {
using namespace ::keymaster;
using secureclock::TimeStampToken;
using ::ndk::ScopedAStatus;
using std::vector;
using LegacyHardwareAuthToken = ::keymaster::HardwareAuthToken;

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return static_cast<keymaster_tag_t>(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return static_cast<Tag>(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

inline void Vec2KmBlob(const vector<uint8_t>& input, KeymasterBlob* blob) {
    blob->Reset(input.size());
    memcpy(blob->writable_data(), input.data(), input.size());
}

inline vector<uint8_t> kmBlob2vector(const keymaster_key_blob_t& blob) {
    vector<uint8_t> result(blob.key_material, blob.key_material + blob.key_material_size);
    return result;
}

inline vector<uint8_t> kmBlob2vector(const keymaster_blob_t& blob) {
    vector<uint8_t> result(blob.data, blob.data + blob.data_length);
    return result;
}

keymaster_error_t legacyHardwareAuthToken(const HardwareAuthToken& aidlToken,
                                          LegacyHardwareAuthToken* legacyToken);

keymaster_error_t encodeTimestampToken(const TimeStampToken& timestampToken,
                                       vector<uint8_t>* encodedToken);

inline ScopedAStatus kmError2ScopedAStatus(const keymaster_error_t value) {
    return (value == KM_ERROR_OK
                ? ScopedAStatus::ok()
                : ScopedAStatus(AStatus_fromServiceSpecificError(static_cast<int32_t>(value))));
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

}  // namespace aidl::android::hardware::security::keymint
