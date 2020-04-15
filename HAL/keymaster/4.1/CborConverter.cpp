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

#include <sstream>
#include <iostream>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <CborConverter.h>

using namespace cppbor;
#define UNUSED(A) A = A

namespace {
template<typename T>
inline T legacyEnumConversion(const unint64_t val) {
    return static_cast<T>(val);
}

}
ErrorCode convertToErrorcode(uint64_t val) {

}

bool convertToTag(uint64_t val, Tag& tag) {
    UNUSED(tag);
    UNUSED(val);
#if 0
    switch (static_cast<TAG>(val)) {
    case TAG::ABC:
        tag = TAG::ABC;
        break;
    case TAG::DEF:
        tag = TAG::DEF;
        break;
    case TAG::GHI:
        tag = TAG::GHI;
        break;
    default:
        return false;
    }
    return true;
#endif
    return false;
}

bool getTagValue(Tag& tag, KeyParameter& keyParam, uint64_t& value) {
    UNUSED(value);
    UNUSED(keyParam);
    UNUSED(tag);
    return false;
}

bool CborConverter::getKeyparameter(const std::pair<const std::unique_ptr<Item>&,
    const std::unique_ptr<Item>&> pair, KeyParameter& keyParam) {
    bool ret = false;
    uint64_t value;
    //TAG will be always uint32_t
    if (!getUint64<uint64_t>(pair.first, 0, value)) {
        return ret;
    }
    if (!convertToTag(value, keyParam.tag)) return false;

    if (MajorType::UINT == getType(pair.second)) {
        if (!getUint64<uint64_t>(pair.second, 0, value)) {
            return ret;
        }
        /* TODO*/
        //Convert value to corresponding enum and assign to keyParam.f
    }
    else if (MajorType::BSTR == getType(pair.second)) {
	std::vector<uint8_t> blob;
        if (!getBinaryArray(pair.second, 0, blob)) {
            return ret;
        }
	keyParam.blob.setToExternal(blob.data(), blob.size());
    }
    return ret;
}

ParseResult CborConverter::decodeData(const std::vector<uint8_t> cborData) {
    return parse(cborData);
}

bool CborConverter::getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<uint8_t>& value) {
    bool ret = false;
    const std::unique_ptr<Item>& strItem = getItemAtPos(item, pos);
    if ((strItem == nullptr) && (MajorType::BSTR != getType(strItem)))
        return ret;

    const Bstr* bstr = strItem.get()->asBstr();
    for (auto bchar : bstr->value()) {
        value.push_back(bchar);
    }
    ret = true;
    return ret;
}


bool CborConverter::getHmacSharingParameters(const std::unique_ptr<Item>& item, const uint32_t pos, HmacSharingParameters& params) {
    std::vector<uint8_t> paramValue;
    bool ret = false;
    //Seed
    if (!getBinaryArray(item, pos, paramValue))
        return ret;
    params.seed.setToExternal(paramValue.data(), paramValue.size());
    paramValue.clear();
    //nonce
    if (!getBinaryArray(item, pos+1, paramValue))
        return ret;
    memcpy(params.nonce.data(), paramValue.data(), paramValue.size());
    ret = true;
    return ret;
}

bool CborConverter::getHardwareAuthToken(const std::unique_ptr<Item>& item, const uint32_t pos, HardwareAuthToken& token) {
    bool ret = false;
    std::vector<uint8_t> mac;
    //challenge
    if (!getUint64<uint64_t>(item, pos, token.challenge))
        return ret;
    //userId
    if (!getUint64<uint64_t>(item, pos+1, token.userId))
        return ret;
    //AuthenticatorId
    if (!getUint64<uint64_t>(item, pos+2, token.authenticatorId))
        return ret;
    //AuthType
    uint64_t authType;
    if (!getUint64<uint64_t>(item, pos+3, authType))
        return ret;
    token.authenticatorType = legacyEnumConversion<HardwareAuthenticatorType>(authType);
    //Timestamp
    if (!getUint64<uint64_t>(item, pos+4, token.timestamp))
        return ret;
    //MAC
    if (!getBinaryArray(item, pos+5, mac))
        return ret;
    token.mac.setToExternal(mac.data(), mac.size());
    ret = true;
    return ret;
}

bool CborConverter::getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<KeyParameter> keyParams) {
    bool ret = false;
    const std::unique_ptr<Item>& mapItem = getItemAtPos(item, pos);
    if ((mapItem == nullptr) && (MajorType::MAP != getType(mapItem)))
        return ret;

    const Map* map = mapItem.get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        KeyParameter param;
        if (!getKeyparameter((*map)[i], param)) {
            return ret;
        }
        keyParams.push_back(param);
    }
    ret = true;
    return ret;
}

bool CborConverter::getErrorCode(const std::unique_ptr<Item>& item, const uint32_t pos, ErrorCode& errorCode) {
    bool ret = false;
    uint64_t errorVal;
    if (!getUint64<uint64_t>(item, pos, errorVal))
        return ret;
    errorCode = legacyEnumConversion<ErrorCode>(errorVal);
    ret = true;
    return ret;
}

