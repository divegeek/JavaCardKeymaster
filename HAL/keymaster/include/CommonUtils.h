/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */


#ifndef KEYMASTER_V4_1_JAVACARD_COMMONUTILS_H_
#define KEYMASTER_V4_1_JAVACARD_COMMONUTILS_H_

#include <android/hardware/keymaster/4.1/types.h>
#include <keymaster/serializable.h>
#include <hardware/keymaster_defs.h>

namespace keymaster {
namespace V4_1 {
namespace javacard {
using ::android::hardware::hidl_vec;
using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::Tag;
using ::android::hardware::keymaster::V4_0::KeyFormat;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::KeyPurpose;
using ::android::hardware::keymaster::V4_0::EcCurve;

inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return static_cast<ErrorCode>(value);
}

inline keymaster_purpose_t legacy_enum_conversion(const KeyPurpose value) {
    return static_cast<keymaster_purpose_t>(value);
}

inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return static_cast<keymaster_key_format_t>(value);
}

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return keymaster_tag_t(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return Tag(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

inline hidl_vec<uint8_t> kmBuffer2hidlVec(const ::keymaster::Buffer& buf) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(buf.peek_read()), buf.available_read());
    return result;
}

inline void blob2Vec(const uint8_t *from, size_t size, std::vector<uint8_t>& to) {
    for(int i = 0; i < size; ++i) {
        to.push_back(from[i]);
    }
}

inline hidl_vec<uint8_t> kmBlob2hidlVec(const keymaster_blob_t& blob) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(blob.data), blob.data_length);
    return result;
}

keymaster_key_param_set_t hidlKeyParams2Km(const hidl_vec<KeyParameter>& keyParams);

hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set);

ErrorCode rsaRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& privateExp, std::vector<uint8_t>&
pubModulus);

ErrorCode ecRawKeyFromPKCS8(const std::vector<uint8_t>& pkcs8Blob, std::vector<uint8_t>& secret, std::vector<uint8_t>&
publicKey, EcCurve& eccurve);

ErrorCode getCertificateChain(std::vector<uint8_t>& chainBuffer, std::vector<std::vector<uint8_t>>& certChain);

uint32_t GetVendorPatchlevel();

class KmParamSet : public keymaster_key_param_set_t {
    public:
        explicit KmParamSet(const hidl_vec<KeyParameter>& keyParams)
            : keymaster_key_param_set_t(hidlKeyParams2Km(keyParams)) {}
        KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
            other.length = 0;
            other.params = nullptr;
        }
        KmParamSet(const KmParamSet&) = delete;
        ~KmParamSet() { delete[] params; }
};

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
#endif //KEYMASTER_V4_1_JAVACARD_COMMONUTILS_H_
