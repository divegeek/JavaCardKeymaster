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
#include <hidl/HidlSupport.h>
#include <CborConverter.h>

using namespace cppbor;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::TagType;
#define UNUSED(A) A = A

bool getTagValue(Tag& tag, KeyParameter& keyParam, uint64_t& value) {
    UNUSED(value);
    UNUSED(keyParam);
    UNUSED(tag);
    return false;
}

bool CborConverter::addKeyparameters(Array& array, const android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams) {
    Map map;
    for(size_t i = 0; i < keyParams.size(); i++) {
        KeyParameter param = keyParams[i];
        TagType tagType = static_cast<TagType>(param.tag & (0xF << 28));
        switch(tagType) {
            case TagType::ENUM:
            case TagType::ENUM_REP:
            case TagType::UINT:
            case TagType::UINT_REP:
                map.add(static_cast<uint64_t>(param.tag), param.f.integer);
            break;
            case TagType::ULONG:
            case TagType::ULONG_REP:
                map.add(static_cast<uint64_t>(param.tag), param.f.longInteger);
            break;
            case TagType::DATE:
                map.add(static_cast<uint64_t>(param.tag), param.f.dateTime);
            break;
            case TagType::BOOL:
                map.add(static_cast<uint64_t>(param.tag), param.f.boolValue);
            break;
            case TagType::BIGNUM:
            case TagType::BYTES:
                map.add(static_cast<uint64_t>(param.tag), (std::vector<uint8_t>(param.blob)));
                break;
            default: 
            /* Invalid skip */
            break;
        }
    }
    array.add(std::move(map));
    return true;
}

bool CborConverter::getKeyparameter(const std::pair<const std::unique_ptr<Item>&,
    const std::unique_ptr<Item>&> pair, KeyParameter& keyParam) {
    bool ret = false;
    uint64_t value;
    //TAG will be always uint32_t
    if (!getUint64<uint64_t>(pair.first, 0, value)) {
        return ret;
    }
    keyParam.tag = static_cast<Tag>(value);

    if (MajorType::UINT == getType(pair.second)) {
        TagType tagType = static_cast<TagType>(keyParam.tag & (0xF << 28));
        switch(tagType) {
            case TagType::ENUM:
            case TagType::ENUM_REP:
            case TagType::UINT:
            case TagType::UINT_REP:
                keyParam.f.integer = static_cast<uint32_t>(value);
            break;
            case TagType::ULONG:
            case TagType::ULONG_REP:
                keyParam.f.longInteger = static_cast<uint32_t>(value);
            break;
            case TagType::DATE:
                keyParam.f.dateTime = static_cast<uint32_t>(value);
            break;
            case TagType::BOOL:
                keyParam.f.boolValue = static_cast<bool>(value);
            break;
            default: 
            /* Invalid skip */
            break;
        }
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

bool CborConverter::addHardwareAuthToken(Array& array, const ::android::hardware::keymaster::V4_0::HardwareAuthToken&
authToken) {
    array.add(authToken.challenge);
    array.add(authToken.userId);
    array.add(authToken.authenticatorId);
    array.add(static_cast<uint64_t>(authToken.authenticatorType));
    array.add(authToken.timestamp);
    array.add((std::vector<uint8_t>(authToken.mac)));
    return true;
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
    token.authenticatorType = static_cast<HardwareAuthenticatorType>(authType);
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

bool CborConverter::getVerificationToken(const std::unique_ptr<Item>& item, const uint32_t pos, VerificationToken&
token) {
    bool ret = false;
    std::vector<uint8_t> mac;
    //challenge
    if (!getUint64<uint64_t>(item, pos, token.challenge))
        return ret;

    //timestamp
    if (!getUint64<uint64_t>(item, pos+1, token.timestamp))
        return ret;

    //List of KeyParameters
    std::vector<KeyParameter> keyParams;
    if (!getKeyParameters(item, pos+2, keyParams))
        return ret;
    token.parametersVerified.setToExternal(keyParams.data(), keyParams.size());

    //AuthenticatorId
    uint64_t val;
    if (!getUint64<uint64_t>(item, pos+3, val))
        return ret;
    token.securityLevel = static_cast<SecurityLevel>(val);
    
    //MAC
    if (!getBinaryArray(item, pos+4, mac))
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
    errorCode = static_cast<ErrorCode>(errorVal);
    ret = true;
    return ret;
}

