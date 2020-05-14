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

#include <CborConverter.h>

bool CborConverter::addKeyparameters(Array& array, const android::hardware::hidl_vec<KeyParameter>& keyParams) {
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

bool CborConverter::getKeyCharacteristics(const std::unique_ptr<Item> &item, const uint32_t pos,
        KeyCharacteristics& keyCharacteristics) {
    bool ret = false;
    std::unique_ptr<Item> arrayItem(nullptr);

    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) && (MajorType::ARRAY != getType(arrayItem)))
        return ret;

    if (!getKeyParameters(arrayItem, 0, keyCharacteristics.softwareEnforced)) {
        return ret;
    }

    if (!getKeyParameters(arrayItem, 1, keyCharacteristics.hardwareEnforced)) {
        return ret;
    }
    //success
    ret = true;
    return ret;
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

bool CborConverter::getMultiBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
        ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>>& data) {
    bool ret = false;
    std::unique_ptr<Item> arrayItem(nullptr);

    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) && (MajorType::ARRAY != getType(arrayItem)))
        return ret;
    const Array* arr = arrayItem.get()->asArray();
    size_t arrSize = arr->size();
    for (int i = 0; i < arrSize; i++) {
        std::vector<uint8_t> innerData;
        if (!getBinaryArray(arrayItem, i, innerData))
            return ret;
        data[i].setToExternal(innerData.data(), innerData.size());
    }
    ret = true; // success
    return ret;
}

bool CborConverter::getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<uint8_t>& value) {
    bool ret = false;
    std::unique_ptr<Item> strItem(nullptr);

    getItemAtPos(item, pos, strItem);
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
    std::unique_ptr<Item> arrayItem(nullptr);

    //1. Get ArrayItem
    //2. First item in the array seed; second item in the array is nonce.

    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) && (MajorType::ARRAY != getType(arrayItem)))
        return ret;

    //Seed
    if (!getBinaryArray(arrayItem, 0, paramValue))
        return ret;
    params.seed.setToExternal(paramValue.data(), paramValue.size());
    paramValue.clear();

    //nonce
    if (!getBinaryArray(arrayItem, 1, paramValue))
        return ret;
    memcpy(params.nonce.data(), paramValue.data(), paramValue.size());
    ret = true;
    return ret;
}

bool CborConverter::addVerificationToken(Array& array, const VerificationToken&
        verificationToken) {
    array.add(verificationToken.challenge);
    array.add(verificationToken.timestamp);
    addKeyparameters(array, verificationToken.parametersVerified);
    array.add(static_cast<uint64_t>(verificationToken.securityLevel));
    array.add((std::vector<uint8_t>(verificationToken.mac)));
    return true;
}

bool CborConverter::addHardwareAuthToken(Array& array, const HardwareAuthToken&
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
    if (!getKeyParameters(item, pos+2, token.parametersVerified))
        return ret;

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

bool CborConverter::getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos, android::hardware::hidl_vec<KeyParameter>& keyParams) {
    bool ret = false;
    std::unique_ptr<Item> mapItem(nullptr);
    getItemAtPos(item, pos, mapItem);
    if ((mapItem == nullptr) && (MajorType::MAP != getType(mapItem)))
        return ret;

    const Map* map = mapItem.get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        KeyParameter param;
        if (!getKeyparameter((*map)[i], param)) {
            return ret;
        }
        keyParams[i] = std::move(param);
    }
    ret = true;
    return ret;
}
