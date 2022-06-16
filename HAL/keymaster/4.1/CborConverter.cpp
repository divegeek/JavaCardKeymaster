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

#include <android-base/logging.h>

#include "CommonUtils.h"

using namespace ::keymaster::V4_1::javacard;
using namespace cppbor;

constexpr int SW_ENFORCED = 0;
constexpr int HW_ENFORCED = 1;


std::optional<uint64_t> CborConverter::getUint64(const std::unique_ptr<Item>& item) {
    if ((item == nullptr) || (MajorType::UINT != getType(item))) {
        return std::nullopt;
    }
    const Uint *uintVal = item.get()->asUint();
    return uintVal->value();
}

std::optional<uint64_t> CborConverter::getUint64(const std::unique_ptr<Item>& item, const uint32_t pos) {
    auto uintItem = getItemAtPos(item, pos);
    if (!uintItem) {
        return std::nullopt;
    }
    return getUint64(*uintItem);
}

bool CborConverter::addKeyparameters(Array& array, const android::hardware::hidl_vec<KeyParameter>& keyParams) {
    Map map;
    std::map<uint64_t, std::vector<uint8_t>> enum_repetition;
    std::map<uint64_t, Array> uint_repetition;
    for (size_t i = 0; i < keyParams.size(); i++) {
        keymaster_tag_type_t tagType = typeFromTag(legacy_enum_conversion(keyParams[i].tag));
        switch(tagType) {
            case KM_ENUM:
            case KM_UINT:
                map.add(static_cast<uint64_t>(keyParams[i].tag), keyParams[i].f.integer);
                break;
            case KM_UINT_REP:
                uint_repetition[static_cast<uint64_t>(keyParams[i].tag)]
                    .add(keyParams[i].f.integer);
                break;
            case KM_ENUM_REP:
                enum_repetition[static_cast<uint64_t>(keyParams[i].tag)]
                    .push_back(static_cast<uint8_t>(keyParams[i].f.integer));
                break;
            case KM_ULONG:
                map.add(static_cast<uint64_t>(keyParams[i].tag), keyParams[i].f.longInteger);
                break;
            case KM_ULONG_REP:
                uint_repetition[static_cast<uint64_t>(keyParams[i].tag)]
                    .add(keyParams[i].f.longInteger);
                break;
            case KM_DATE:
                map.add(static_cast<uint64_t>(keyParams[i].tag), keyParams[i].f.dateTime);
                break;
            case KM_BOOL:
                map.add(static_cast<uint64_t>(keyParams[i].tag),
                        static_cast<uint8_t>(keyParams[i].f.boolValue));
                break;
            case KM_BIGNUM:
            case KM_BYTES:
                map.add(static_cast<uint64_t>(keyParams[i].tag),
                        (std::vector<uint8_t>(keyParams[i].blob)));
                break;
            case KM_INVALID:
                break;
        }
    }
    for (auto const& [key, val] : enum_repetition ) {
        Bstr bstr(val);
        map.add(key, std::move(bstr));
    }
    for (auto & [key, val] : uint_repetition ) {
        map.add(key, std::move(val));
    }
    array.add(std::move(map));
    return true;
}

std::optional<KeyCharacteristics>
CborConverter::getKeyCharacteristics(const std::unique_ptr<Item> &item, const uint32_t pos) {
    KeyCharacteristics keyCharacteristics;
    auto arrayItem = getItemAtPos(item, pos);
    if (!arrayItem || (MajorType::ARRAY != getType(*arrayItem)))
        return std::nullopt;

    auto optSwEnf = getKeyParameters(*arrayItem, SW_ENFORCED);
    if (!optSwEnf) {
        return std::nullopt;
    }
    keyCharacteristics.softwareEnforced = std::move(*optSwEnf);

    auto optHwEnf = getKeyParameters(*arrayItem, HW_ENFORCED);
    if (!optHwEnf) {
        return std::nullopt;
    }
    keyCharacteristics.hardwareEnforced = std::move(*optHwEnf);
    return keyCharacteristics;

}

std::optional<std::vector<KeyParameter>>
CborConverter::getKeyParameter(const std::pair<const std::unique_ptr<Item>&,
                const std::unique_ptr<Item>&> pair) {
    std::vector<KeyParameter> keyParams;
    Tag key;

    auto optKey = getUint64(pair.first);
    if (!optKey) {
        return std::nullopt;
    }
    key = static_cast<Tag>(optKey.value());

    /* Get the TagType from the Tag */
   keymaster_tag_type_t tagType = typeFromTag(legacy_enum_conversion(key));
    switch(tagType) {
        case KM_ENUM_REP:
            {
                /* ENUM_REP contains values encoded in a Byte string */
                const Bstr* bstr = pair.second.get()->asBstr();
                if(bstr == nullptr) return std::nullopt;
                for (auto bchar : bstr->value()) {
                    KeyParameter keyParam;
                    keyParam.tag = key;
                    keyParam.f.integer = bchar;
                    keyParams.push_back(std::move(keyParam));
                }
                return keyParams;
            }
            break;
        case KM_ENUM:
        case KM_UINT:
            {
                KeyParameter keyParam;
                keyParam.tag = key;
                auto optVal = getUint64(pair.second);
                if(!optVal) {
                    return std::nullopt;
                }
                keyParam.f.integer = static_cast<uint32_t>(optVal.value());
                keyParams.push_back(std::move(keyParam));
                return keyParams;
            }
            break;
        case KM_ULONG:
            {
                KeyParameter keyParam;
                keyParam.tag = key;
                auto optVal = getUint64(pair.second);
                if(!optVal) {
                    return std::nullopt;
                }
                keyParam.f.longInteger = optVal.value();
                keyParams.push_back(std::move(keyParam));
                return keyParams;
            }
            break;
        case KM_UINT_REP:
            {
                /* UINT_REP contains values encoded in a Array */
                Array* array = const_cast<Array*>(pair.second.get()->asArray());
                if(array == nullptr) return std::nullopt;
                for(int i = 0; i < array->size(); i++) {
                    KeyParameter keyParam;
                    keyParam.tag = key;
                    const std::unique_ptr<Item>& item = array->get(i);
                    auto optVal = getUint64(item);
                    if(!optVal) {
                        return std::nullopt;
                    }
                    keyParam.f.integer = static_cast<uint32_t>(optVal.value());
                    keyParams.push_back(std::move(keyParam));

                }
                return keyParams;
            }
            break;
        case KM_ULONG_REP:
            {
                /* ULONG_REP contains values encoded in a Array */
                Array* array = const_cast<Array*>(pair.second.get()->asArray());
                if(array == nullptr) return std::nullopt;
                for(int i = 0; i < array->size(); i++) {
                    KeyParameter keyParam;
                    keyParam.tag = key;
                    const std::unique_ptr<Item>& item = array->get(i);
                    auto optVal = getUint64(item);
                    if(!optVal) {
                        return std::nullopt;
                    }
                    keyParam.f.longInteger = optVal.value();
                    keyParams.push_back(std::move(keyParam));

                }
                return keyParams;
            }
            break;
        case KM_DATE:
            {
                KeyParameter keyParam;
                keyParam.tag = key;
                auto optVal = getUint64(pair.second);
                if(!optVal) {
                    return std::nullopt;
                }
                keyParam.f.dateTime = optVal.value();
                keyParams.push_back(std::move(keyParam));
                return keyParams;
            }
            break;
        case KM_BOOL:
            {
                KeyParameter keyParam;
                keyParam.tag = key;
                auto optVal = getUint64(pair.second);
                if(!optVal) {
                    return std::nullopt;
                }
                keyParam.f.boolValue = static_cast<bool>(optVal.value());
                keyParams.push_back(std::move(keyParam));
                return keyParams;
            }
            break;
        case KM_BYTES:
            {
                KeyParameter keyParam;
                keyParam.tag = key;
                const Bstr* bstr = pair.second.get()->asBstr();
                if(bstr == nullptr) return std::nullopt;
                keyParam.blob = bstr->value();
                keyParams.push_back(std::move(keyParam));
                return keyParams;
            }
            break;
        case KM_INVALID:
        case KM_BIGNUM:
            break;
    }
    return std::nullopt;
}

std::optional<std::vector<std::vector<uint8_t>>>
CborConverter::getCertChain(const std::unique_ptr<Item>& item, const uint32_t pos) {
    std::vector<std::vector<uint8_t>> data;
    auto arrayItem = getItemAtPos(item, pos);
    if (!arrayItem  || (MajorType::ARRAY != getType(*arrayItem))) {
        return std::nullopt;
    }
    size_t arrSize = arrayItem->get()->asArray()->size();
    for (int i = 0; i < arrSize; i++) {
        auto optTemp = getByteArrayVec(*arrayItem, i);
        if (!optTemp) {
            return std::nullopt;
        }
        data.push_back(std::move(*optTemp));
    }
    return data;
}

std::optional<::android::hardware::hidl_vec<uint8_t>>
CborConverter::getByteArrayHidlVec(const std::unique_ptr<Item>& item, const uint32_t pos) {
    auto strItem = getItemAtPos(item, pos);
    if (!strItem || (MajorType::BSTR != getType(*strItem)))
        return std::nullopt;

    return strItem->get()->asBstr()->value();
}

std::optional<::android::hardware::hidl_string>
CborConverter::getByteArrayHidlStr(const std::unique_ptr<Item>& item, const uint32_t pos) {
    auto vec = getByteArrayVec(item, pos);
    if(!vec) {
        return std::nullopt;
    }
    std::string str(vec->begin(), vec->end());
    return str;
}

std::optional<std::vector<uint8_t>>
CborConverter::getByteArrayVec(const std::unique_ptr<Item>& item, const uint32_t pos) {
    auto strItem = getItemAtPos(item, pos);
    if (!strItem || (MajorType::BSTR != getType(*strItem)))
        return std::nullopt;

    return strItem->get()->asBstr()->value();
}

std::optional<HmacSharingParameters>
CborConverter::getHmacSharingParameters(const std::unique_ptr<Item>& item, const uint32_t pos) {
    std::vector<uint8_t> paramValue;
    HmacSharingParameters params;
    //1. Get ArrayItem
    auto arrayItem = getItemAtPos(item, pos);
    //2. First item in the array seed; second item in the array is nonce.
    if (!arrayItem || (MajorType::ARRAY != getType(*arrayItem)))
        return std::nullopt;

    auto optSeed = getByteArrayHidlVec(*arrayItem, 0);
    auto optNonce = getByteArrayVec(*arrayItem, 1);
    if (!optSeed || !optNonce) {
        return std::nullopt;
    }
    params.seed = std::move(*optSeed);
    memcpy(params.nonce.data(), optNonce->data(), optNonce->size());
    return params;
}

bool CborConverter::addVerificationToken(Array& array, const VerificationToken&
        verificationToken, std::vector<uint8_t>& encodedParamsVerified) {
    Array vToken;
    vToken.add(verificationToken.challenge);
    vToken.add(verificationToken.timestamp);
    vToken.add(std::move(encodedParamsVerified));
    vToken.add(static_cast<uint64_t>(verificationToken.securityLevel));
    vToken.add((std::vector<uint8_t>(verificationToken.mac)));
    array.add(std::move(vToken));
    return true;
}

bool CborConverter::addHardwareAuthToken(Array& array, const HardwareAuthToken&
        authToken) {
    Array hwAuthToken;
    hwAuthToken.add(authToken.challenge);
    hwAuthToken.add(authToken.userId);
    hwAuthToken.add(authToken.authenticatorId);
    hwAuthToken.add(static_cast<uint64_t>(authToken.authenticatorType));
    hwAuthToken.add(authToken.timestamp);
    hwAuthToken.add((std::vector<uint8_t>(authToken.mac)));
    array.add(std::move(hwAuthToken));
    return true;
}

std::optional<android::hardware::hidl_vec<KeyParameter>>
CborConverter::getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos) {
    android::hardware::hidl_vec<KeyParameter> hidlVecParams;
    std::vector<KeyParameter> params;
    auto mapItem = getItemAtPos(item, pos);
    if (!mapItem || (MajorType::MAP != getType(*mapItem)))
        return std::nullopt;

    const Map* map = mapItem->get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        auto optKeyParams = getKeyParameter((*map)[i]);
        if (optKeyParams) {
            params.insert(params.end(), optKeyParams->begin(), optKeyParams->end());
        } else {
            return std::nullopt;
        }
    }
    hidlVecParams.resize(params.size());
    hidlVecParams = params;
    return hidlVecParams;
}

std::tuple<std::unique_ptr<cppbor::Item>, ErrorCode>
CborConverter::decodeData(const std::vector<uint8_t> &response, bool hasErrorCode) {
    const uint8_t *pos;
    std::unique_ptr<cppbor::Item> item(nullptr);
    std::string message;
    ErrorCode errorCode = ErrorCode::OK;

    std::tie(item, pos, message) = cppbor::parse(response);

    if (item != nullptr && hasErrorCode) {
        if (cppbor::MajorType::ARRAY == getType(item)) {
            auto optErr  = getErrorCode(item, 0);
            if (!optErr) {
                item = nullptr;
            } else {
                errorCode = optErr.value();
            }

        } else if (cppbor::MajorType::UINT == getType(item)) {
            auto optErr  = getUint64(item);
            if (optErr) {
                errorCode = static_cast<ErrorCode>(optErr.value());
            }
            item = nullptr; /*Already read the errorCode. So no need of sending item to client */
        }
    }
    return {std::move(item), errorCode};
}

std::optional<std::unique_ptr<Item>>
CborConverter::getItemAtPos(const std::unique_ptr<cppbor::Item> &item, const uint32_t pos) {
    if (cppbor::MajorType::ARRAY != getType(item)) {
        return std::nullopt;
    }
    Array *arr = item.get()->asArray();
    if (arr->size() < (pos + 1)) {
        return std::nullopt;
    }
    return std::move(arr->get(pos));
}

std::optional<ErrorCode> 
CborConverter::getErrorCode(const std::unique_ptr<cppbor::Item> &item, const uint32_t pos) {
    auto optErrorVal = getUint64(item, pos);
    if (!optErrorVal) {
        return std::nullopt;
    }
    return static_cast<ErrorCode>(*optErrorVal);
}
