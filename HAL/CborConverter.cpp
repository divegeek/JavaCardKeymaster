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

#include "CborConverter.h"

#include <map>
#include <string>

#include "JavacardKeyMintUtils.h"

namespace keymint::javacard {
using namespace cppbor;
using namespace aidl::android::hardware::security::keymint;
using namespace aidl::android::hardware::security::secureclock;
using namespace aidl::android::hardware::security::sharedsecret;
using std::string;
using std::unique_ptr;
using std::vector;

constexpr int SB_ENFORCED = 0;
constexpr int TEE_ENFORCED = 1;
constexpr int SW_ENFORCED = 2;

bool CborConverter::addAttestationKey(Array& array,
                                      const std::optional<AttestationKey>& attestationKey) {
    if (attestationKey.has_value()) {
        array.add(Bstr(attestationKey->keyBlob));
        addKeyparameters(array, attestationKey->attestKeyParams);
        array.add(Bstr(attestationKey->issuerSubjectName));
    } else {
        array.add(std::move(Bstr(vector<uint8_t>(0))));
        array.add(std::move(Map()));
        array.add(std::move(Bstr(vector<uint8_t>(0))));
    }
    return true;
}

bool CborConverter::addKeyparameters(Array& array, const vector<KeyParameter>& keyParams) {
    keymaster_key_param_set_t paramSet = km_utils::aidlKeyParams2Km(keyParams);
    Map map;
    std::map<uint64_t, vector<uint8_t>> enum_repetition;
    std::map<uint64_t, Array> uint_repetition;
    for (size_t i = 0; i < paramSet.length; i++) {
        const auto& param = paramSet.params[i];
        switch (km_utils::typeFromTag(param.tag)) {
        case KM_ENUM:
            map.add(static_cast<uint64_t>(param.tag), param.enumerated);
            break;
        case KM_UINT:
            map.add(static_cast<uint64_t>(param.tag), param.integer);
            break;
        case KM_UINT_REP:
            uint_repetition[static_cast<uint64_t>(param.tag)].add(param.integer);
            break;
        case KM_ENUM_REP:
            enum_repetition[static_cast<uint64_t>(param.tag)].push_back(
                static_cast<uint8_t>(param.enumerated));
            break;
        case KM_ULONG:
            map.add(static_cast<uint64_t>(param.tag), param.long_integer);
            break;
        case KM_ULONG_REP:
            uint_repetition[static_cast<uint64_t>(param.tag & 0x00000000ffffffff)].add(
                param.long_integer);
            break;
        case KM_DATE:
            map.add(static_cast<uint64_t>(param.tag), param.date_time);
            break;
        case KM_BOOL:
            map.add(static_cast<uint64_t>(param.tag), static_cast<uint8_t>(param.boolean));
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            map.add(static_cast<uint64_t>(param.tag & 0x00000000ffffffff),
                    km_utils::kmBlob2vector(param.blob));
            break;
        case KM_INVALID:
            break;
        }
    }

    for (auto const& [key, val] : enum_repetition) {
        Bstr bstr(val);
        map.add(key, std::move(bstr));
    }

    for (auto& [key, val] : uint_repetition) {
        map.add(key, std::move(val));
    }
    array.add(std::move(map));
    return true;
}

// Array of three maps
std::optional<vector<KeyCharacteristics>> CborConverter::getKeyCharacteristics(const unique_ptr<Item>& item, const uint32_t pos) {
    vector<KeyCharacteristics> keyCharacteristics;
    auto arrayItem = getItemAtPos(item, pos);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem.value()))) {
        return std::nullopt;
    }
    KeyCharacteristics swEnf{SecurityLevel::KEYSTORE, {}};
    KeyCharacteristics teeEnf{SecurityLevel::TRUSTED_ENVIRONMENT, {}};
    KeyCharacteristics sbEnf{SecurityLevel::STRONGBOX, {}};

    auto optSbEnf = getKeyParameters(arrayItem.value(), SB_ENFORCED);
    if (!optSbEnf) {
        return std::nullopt;
    }
    sbEnf.authorizations = std::move(optSbEnf.value());
    auto optTeeEnf = getKeyParameters(arrayItem.value(), TEE_ENFORCED);
    if (!optTeeEnf) {
        return std::nullopt;
    }
    teeEnf.authorizations = std::move(optTeeEnf.value());
    auto optSwEnf = getKeyParameters(arrayItem.value(), SW_ENFORCED);
    if (!optSwEnf) {
        return std::nullopt;
    }
    swEnf.authorizations = std::move(optSwEnf.value());
    // VTS will fail if the authorizations list is empty.
    if (!sbEnf.authorizations.empty()) keyCharacteristics.push_back(std::move(sbEnf));
    if (!teeEnf.authorizations.empty()) keyCharacteristics.push_back(std::move(teeEnf));
    if (!swEnf.authorizations.empty()) keyCharacteristics.push_back(std::move(swEnf));
    return keyCharacteristics;
}

std::optional<std::vector<KeyParameter>>
CborConverter::getKeyParameter(const std::pair<const std::unique_ptr<Item>&,
                const std::unique_ptr<Item>&> pair) {
    std::vector<KeyParameter> keyParams;
    keymaster_tag_t key;
    auto optValue = getUint64<uint64_t>(pair.first);
    if (!optValue) {
        return std::nullopt;
    }
    key = static_cast<keymaster_tag_t>(optValue.value());
    switch (keymaster_tag_get_type(key)) {
    case KM_ENUM_REP: {
        /* ENUM_REP contains values encoded in a Bit string */
        const Bstr* bstr = pair.second.get()->asBstr();
        if (bstr == nullptr) {
            return std::nullopt;
        }
        for (auto bchar : bstr->value()) {
            keymaster_key_param_t keyParam;
            keyParam.tag = key;
            keyParam.enumerated = bchar;
            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
        }
    } break;
    case KM_ENUM: {
        keymaster_key_param_t keyParam;
        keyParam.tag = key;
        if (!(optValue = getUint64<uint64_t>(pair.second))) {
            return std::nullopt;
        }
        keyParam.enumerated = static_cast<uint32_t>(optValue.value());
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_UINT: {
        keymaster_key_param_t keyParam;
        keyParam.tag = key;
        if (!(optValue = getUint64<uint64_t>(pair.second))) {
            return std::nullopt;
        }
        keyParam.integer = static_cast<uint32_t>(optValue.value());
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_ULONG: {
        keymaster_key_param_t keyParam;
        keyParam.tag = key;
        if (!(optValue = getUint64<uint64_t>(pair.second))) {
            return std::nullopt;
        }
        keyParam.long_integer = optValue.value();
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_UINT_REP: {
        /* UINT_REP contains values encoded in a Array */
        Array* array = const_cast<Array*>(pair.second.get()->asArray());
        if (array == nullptr) return std::nullopt;
        for (int i = 0; i < array->size(); i++) {
            keymaster_key_param_t keyParam;
            keyParam.tag = key;
            std::unique_ptr<Item> item = std::move(array->get(i));
            if (!(optValue = getUint64<uint64_t>(item))) {
                return std::nullopt;
            }
            keyParam.integer = static_cast<uint32_t>(optValue.value());
            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
        }
    } break;
    case KM_ULONG_REP: {
        /* ULONG_REP contains values encoded in a Array */
        Array* array = const_cast<Array*>(pair.second.get()->asArray());
        if (array == nullptr) return std::nullopt;
        for (int i = 0; i < array->size(); i++) {
            keymaster_key_param_t keyParam;
            keyParam.tag = key;
            std::unique_ptr<Item> item = std::move(array->get(i));
            if (!(optValue = getUint64<uint64_t>(item))) {
                return std::nullopt;
            }
            keyParam.long_integer = optValue.value();
            keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
        }
    } break;
    case KM_DATE: {
        keymaster_key_param_t keyParam;
        keyParam.tag = key;
        if (!(optValue = getUint64<uint64_t>(pair.second))) {
            return std::nullopt;
        }
        keyParam.date_time = optValue.value();
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_BOOL: {
        keymaster_key_param_t keyParam;
        keyParam.tag = key;
        if (!(optValue = getUint64<uint64_t>(pair.second))) {
            return std::nullopt;
        }
        // TODO re-check the logic below
        keyParam.boolean = static_cast<bool>(optValue.value());
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    case KM_BYTES: {
        keymaster_key_param_t keyParam;
        keyParam.tag = key;
        const Bstr* bstr = pair.second.get()->asBstr();
        if (bstr == nullptr) return std::nullopt;
        keyParam.blob.data = bstr->value().data();
        keyParam.blob.data_length = bstr->value().size();
        keyParams.push_back(km_utils::kmParam2Aidl(keyParam));
    } break;
    default:
        /* Invalid - return error */
        return std::nullopt;
    }
    return keyParams;
}

// array of a blobs
std::optional<vector<Certificate>> CborConverter::getCertificateChain(const std::unique_ptr<Item>& item, const uint32_t pos) {
    vector<Certificate> certChain;
    auto arrayItem = getItemAtPos(item, pos);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem.value()))) return std::nullopt;

    const Array* arr = arrayItem.value().get()->asArray();
    for (int i = 0; i < arr->size(); i++) {
        Certificate cert;
        auto optTemp = getByteArrayVec(arrayItem.value(), i);
        if (!optTemp) return std::nullopt;
        cert.encodedCertificate = std::move(optTemp.value());
        certChain.push_back(std::move(cert));
    }
    return certChain;
}

std::optional<string> CborConverter::getByteArrayStr(const unique_ptr<Item>& item, const uint32_t pos) {
    auto optTemp = getByteArrayVec(item, pos);
    if (!optTemp) {
        return std::nullopt;
    }
    std::string str(optTemp->begin(), optTemp->end());
    return str;
}

std::optional<std::vector<uint8_t>> CborConverter::getByteArrayVec(const unique_ptr<Item>& item, const uint32_t pos) {
    auto strItem = getItemAtPos(item, pos);
    if ((strItem == nullptr) || (MajorType::BSTR != getType(strItem.value()))) {
        return std::nullopt;
    }
    const Bstr* bstr = strItem.value().get()->asBstr();
    return bstr->value();
}

std::optional<SharedSecretParameters> CborConverter::getSharedSecretParameters(const unique_ptr<Item>& item, const uint32_t pos) {
    SharedSecretParameters params;
    // Array [seed, nonce]
    auto arrayItem = getItemAtPos(item, pos);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem.value()))) {
        return std::nullopt;
    }
    auto optSeed = getByteArrayVec(arrayItem.value(), 0);
    auto optNonce = getByteArrayVec(arrayItem.value(), 1);
    if (!optSeed || !optNonce) {
        return std::nullopt;
    }
    params.seed = std::move(optSeed.value());
    params.nonce = std::move(optNonce.value());
    return params;
}

bool CborConverter::addSharedSecretParameters(Array& array,
                                              const vector<SharedSecretParameters>& params) {
    Array cborParamsVec;
    for (auto param : params) {
        Array cborParam;
        cborParam.add(Bstr(param.seed));
        cborParam.add(Bstr(param.nonce));
        cborParamsVec.add(std::move(cborParam));
    }
    array.add(std::move(cborParamsVec));
    return true;
}

bool CborConverter::addTimeStampToken(Array& array, const TimeStampToken& token) {
    Array vToken;
    vToken.add(static_cast<uint64_t>(token.challenge));
    vToken.add(static_cast<uint64_t>(token.timestamp.milliSeconds));
    vToken.add((std::vector<uint8_t>(token.mac)));
    array.add(std::move(vToken));
    return true;
}

bool CborConverter::addHardwareAuthToken(Array& array, const HardwareAuthToken& authToken) {

    Array hwAuthToken;
    hwAuthToken.add(static_cast<uint64_t>(authToken.challenge));
    hwAuthToken.add(static_cast<uint64_t>(authToken.userId));
    hwAuthToken.add(static_cast<uint64_t>(authToken.authenticatorId));
    hwAuthToken.add(static_cast<uint64_t>(authToken.authenticatorType));
    hwAuthToken.add(static_cast<uint64_t>(authToken.timestamp.milliSeconds));
    hwAuthToken.add((std::vector<uint8_t>(authToken.mac)));
    array.add(std::move(hwAuthToken));
    return true;
}

std::optional<TimeStampToken> CborConverter::getTimeStampToken(const unique_ptr<Item>& item, const uint32_t pos) {
    TimeStampToken token;
    // {challenge, timestamp, Mac}
    auto optChallenge = getUint64<uint64_t>(item, pos);
    auto optTimestampMillis = getUint64<uint64_t>(item, pos + 1);
    auto optTemp = getByteArrayVec(item, pos + 2);
    if (!optChallenge || !optTimestampMillis || !optTemp) {
        return std::nullopt;
    }
    token.mac = std::move(optTemp.value());
    token.challenge = static_cast<long>(std::move(optChallenge.value()));
    token.timestamp.milliSeconds = static_cast<long>(std::move(optTimestampMillis.value()));
    return token;
}

std::optional<Array> CborConverter::getArrayItem(const std::unique_ptr<Item>& item, const uint32_t pos) {
    Array array;
    auto arrayItem = getItemAtPos(item, pos);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem.value()))) {
        return std::nullopt;
    }
    array = std::move(*(arrayItem.value().get()->asArray()));
    return array;
}

std::optional<Map> CborConverter::getMapItem(const std::unique_ptr<Item>& item, const uint32_t pos) {
    Map map;
    auto mapItem = getItemAtPos(item, pos);
    if ((mapItem == nullptr) || (MajorType::MAP != getType(mapItem.value()))) {
        return std::nullopt;
    }
    map = std::move(*(mapItem.value().get()->asMap()));
    return map;
}

std::optional<vector<KeyParameter>> CborConverter::getKeyParameters(const unique_ptr<Item>& item, const uint32_t pos) {
    vector<KeyParameter> params;
    auto mapItem = getItemAtPos(item, pos);
    if ((mapItem == nullptr) || (MajorType::MAP != getType(mapItem.value()))) return std::nullopt;
    const Map* map = mapItem.value().get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        auto optKeyParams = getKeyParameter((*map)[i]);
        if (optKeyParams) {
            params.insert(params.end(), optKeyParams->begin(), optKeyParams->end());
        } else {
          return std::nullopt;
        }
    }
    return params;
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
CborConverter::decodeData(const std::vector<uint8_t>& response) {
    auto [item, pos, message] = parse(response);
    if (!item || MajorType::ARRAY != getType(item)) {
        return {nullptr, KM_ERROR_UNKNOWN_ERROR};
    }
    auto optErrorCode = getErrorCode(item, 0);
    if (!optErrorCode) {
        return {nullptr, KM_ERROR_UNKNOWN_ERROR};
    }
    return {std::move(item), optErrorCode.value()};
}

}  // namespace keymint::javacard
