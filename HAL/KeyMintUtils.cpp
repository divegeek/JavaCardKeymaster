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

#define LOG_TAG "android.hardware.security.keymint-impl"
#include <android-base/logging.h>

#include "KeyMintUtils.h"
#include <keymaster/wrapped_key.h>

namespace keymint::javacard {

using namespace ::keymaster;
using namespace keymaster::javacard::test;
namespace {

KeyParameter kmEnumParam2Aidl(const keymaster_key_param_t& param) {
    switch (param.tag) {
    case KM_TAG_PURPOSE:
        return KeyParameter{Tag::PURPOSE, KeyParameterValue::make<KeyParameterValue::keyPurpose>(
                                              static_cast<KeyPurpose>(param.enumerated))};
    case KM_TAG_ALGORITHM:
        return KeyParameter{Tag::ALGORITHM, KeyParameterValue::make<KeyParameterValue::algorithm>(
                                                static_cast<Algorithm>(param.enumerated))};
    case KM_TAG_BLOCK_MODE:
        return KeyParameter{Tag::BLOCK_MODE, KeyParameterValue::make<KeyParameterValue::blockMode>(
                                                 static_cast<BlockMode>(param.enumerated))};
    case KM_TAG_DIGEST:
        return KeyParameter{Tag::DIGEST, KeyParameterValue::make<KeyParameterValue::digest>(
                                             static_cast<Digest>(param.enumerated))};
    case KM_TAG_PADDING:
        return KeyParameter{Tag::PADDING, KeyParameterValue::make<KeyParameterValue::paddingMode>(
                                              static_cast<PaddingMode>(param.enumerated))};
    case KM_TAG_EC_CURVE:
        return KeyParameter{Tag::EC_CURVE, KeyParameterValue::make<KeyParameterValue::ecCurve>(
                                               static_cast<EcCurve>(param.enumerated))};
    case KM_TAG_USER_AUTH_TYPE:
        return KeyParameter{Tag::USER_AUTH_TYPE,
                            KeyParameterValue::make<KeyParameterValue::hardwareAuthenticatorType>(
                                static_cast<HardwareAuthenticatorType>(param.enumerated))};
    case KM_TAG_ORIGIN:
        return KeyParameter{Tag::ORIGIN, KeyParameterValue::make<KeyParameterValue::origin>(
                                             static_cast<KeyOrigin>(param.enumerated))};
    case KM_TAG_BLOB_USAGE_REQUIREMENTS:
    case KM_TAG_KDF:
    default:
        return KeyParameter{Tag::INVALID, false};
    }
}

keymaster_key_param_t kInvalidTag{.tag = KM_TAG_INVALID, .integer = 0};

template <KeyParameterValue::Tag aidl_tag>
keymaster_key_param_t aidlEnumVal2Km(keymaster_tag_t km_tag, const KeyParameterValue& value) {
    return value.getTag() == aidl_tag
               ? keymaster_param_enum(km_tag, static_cast<uint32_t>(value.get<aidl_tag>()))
               : kInvalidTag;
}

keymaster_key_param_t aidlEnumParam2Km(const KeyParameter& param) {
    auto tag = legacy_enum_conversion(param.tag);
    switch (tag) {
    case KM_TAG_PURPOSE:
        return aidlEnumVal2Km<KeyParameterValue::keyPurpose>(tag, param.value);
    case KM_TAG_ALGORITHM:
        return aidlEnumVal2Km<KeyParameterValue::algorithm>(tag, param.value);
    case KM_TAG_BLOCK_MODE:
        return aidlEnumVal2Km<KeyParameterValue::blockMode>(tag, param.value);
    case KM_TAG_DIGEST:
    case KM_TAG_RSA_OAEP_MGF_DIGEST:
        return aidlEnumVal2Km<KeyParameterValue::digest>(tag, param.value);
    case KM_TAG_PADDING:
        return aidlEnumVal2Km<KeyParameterValue::paddingMode>(tag, param.value);
    case KM_TAG_EC_CURVE:
        return aidlEnumVal2Km<KeyParameterValue::ecCurve>(tag, param.value);
    case KM_TAG_USER_AUTH_TYPE:
        return aidlEnumVal2Km<KeyParameterValue::hardwareAuthenticatorType>(tag, param.value);
    case KM_TAG_ORIGIN:
        return aidlEnumVal2Km<KeyParameterValue::origin>(tag, param.value);
    case KM_TAG_BLOB_USAGE_REQUIREMENTS:
    case KM_TAG_KDF:
    default:
        CHECK(false) << "Unknown or unused enum tag: Something is broken";
        return keymaster_param_enum(tag, false);
    }
}

}  // namespace

vector<uint8_t> authToken2AidlVec(const HardwareAuthToken& token) {
    static_assert(1 /* version size */ + sizeof(token.challenge) + sizeof(token.userId) +
                          sizeof(token.authenticatorId) + sizeof(token.authenticatorType) +
                          sizeof(token.timestamp) + 32 /* HMAC size */
                      == sizeof(hw_auth_token_t),
                  "HardwareAuthToken content size does not match hw_auth_token_t size");

    vector<uint8_t> result;

    if (token.mac.size() < 32) return result;

    result.resize(sizeof(hw_auth_token_t));
    auto pos = result.begin();
    *pos++ = 0;  // Version byte
    pos = copy_bytes_to_iterator(token.challenge, pos);
    pos = copy_bytes_to_iterator(token.userId, pos);
    pos = copy_bytes_to_iterator(token.authenticatorId, pos);
    pos = copy_bytes_to_iterator(hton(static_cast<uint32_t>(token.authenticatorType)), pos);
    pos = copy_bytes_to_iterator(hton(token.timestamp.milliSeconds), pos);
    pos = std::copy(token.mac.data(), token.mac.data() + token.mac.size(), pos);

    return result;
}

KeyParameter kmParam2Aidl(const keymaster_key_param_t& param) {
    auto tag = legacy_enum_conversion(param.tag);
    switch (typeFromTag(param.tag)) {
    case KM_ENUM:
    case KM_ENUM_REP:
        return kmEnumParam2Aidl(param);
        break;

    case KM_UINT:
    case KM_UINT_REP:
        return KeyParameter{tag,
                            KeyParameterValue::make<KeyParameterValue::integer>(param.integer)};

    case KM_ULONG:
    case KM_ULONG_REP:
        return KeyParameter{
            tag, KeyParameterValue::make<KeyParameterValue::longInteger>(param.long_integer)};
        break;

    case KM_DATE:
        return KeyParameter{tag,
                            KeyParameterValue::make<KeyParameterValue::dateTime>(param.date_time)};
        break;

    case KM_BOOL:
        return KeyParameter{tag, param.boolean};
        break;

    case KM_BIGNUM:
    case KM_BYTES:
        return {tag, KeyParameterValue::make<KeyParameterValue::blob>(
                         std::vector(param.blob.data, param.blob.data + param.blob.data_length))};
        break;

    case KM_INVALID:
    default:
        CHECK(false) << "Unknown or unused tag type: Something is broken";
        return KeyParameter{Tag::INVALID, false};
        break;
    }
}

vector<KeyParameter> kmParamSet2Aidl(const keymaster_key_param_set_t& set) {
    vector<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr) return result;

    result.reserve(set.length);
    for (size_t i = 0; i < set.length; ++i) {
        result.push_back(kmParam2Aidl(set.params[i]));
    }
    return result;
}

keymaster_key_param_set_t aidlKeyParams2Km(const vector<KeyParameter>& keyParams) {
    keymaster_key_param_set_t set;

    set.params = static_cast<keymaster_key_param_t*>(
        malloc(keyParams.size() * sizeof(keymaster_key_param_t)));
    set.length = keyParams.size();

    for (size_t i = 0; i < keyParams.size(); ++i) {
        const auto& param = keyParams[i];
        auto tag = legacy_enum_conversion(param.tag);
        switch (typeFromTag(tag)) {

        case KM_ENUM:
        case KM_ENUM_REP:
            set.params[i] = aidlEnumParam2Km(param);
            break;

        case KM_UINT:
        case KM_UINT_REP:
            set.params[i] =
                param.value.getTag() == KeyParameterValue::integer
                    ? keymaster_param_int(tag, param.value.get<KeyParameterValue::integer>())
                    : kInvalidTag;
            break;

        case KM_ULONG:
        case KM_ULONG_REP:
            set.params[i] =
                param.value.getTag() == KeyParameterValue::longInteger
                    ? keymaster_param_long(tag, param.value.get<KeyParameterValue::longInteger>())
                    : kInvalidTag;
            break;

        case KM_DATE:
            set.params[i] =
                param.value.getTag() == KeyParameterValue::dateTime
                    ? keymaster_param_date(tag, param.value.get<KeyParameterValue::dateTime>())
                    : kInvalidTag;
            break;

        case KM_BOOL:
            set.params[i] = keymaster_param_bool(tag);
            break;

        case KM_BIGNUM:
        case KM_BYTES:
            if (param.value.getTag() == KeyParameterValue::blob) {
                const auto& value = param.value.get<KeyParameterValue::blob>();
                uint8_t* copy = static_cast<uint8_t*>(malloc(value.size()));
                std::copy(value.begin(), value.end(), copy);
                set.params[i] = keymaster_param_blob(tag, copy, value.size());
            } else {
                set.params[i] = kInvalidTag;
            }
            break;

        case KM_INVALID:
        default:
            CHECK(false) << "Invalid tag: Something is broken";
            set.params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }

    return set;
}

}  // namespace keymint::javacard
