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
#include <android-base/logging.h>

bool CborConverter::addKeyparameters(Array& array, const android::hardware::hidl_vec<KeyParameter>& keyParams) {
    Map map;
    std::map<uint64_t, std::vector<uint8_t>> enum_repetition;
    std::map<uint64_t, Array> uint_repetition;
    for(size_t i = 0; i < keyParams.size(); i++) {
        KeyParameter param = keyParams[i];
        TagType tagType = static_cast<TagType>(param.tag & (0xF << 28));
        switch(tagType) {
            case TagType::ENUM:
            case TagType::UINT:
                map.add(static_cast<uint64_t>(param.tag), param.f.integer);
                break;
            case TagType::UINT_REP:
                uint_repetition[static_cast<uint64_t>(param.tag)].add(param.f.integer);
                break;
            case TagType::ENUM_REP:
                enum_repetition[static_cast<uint64_t>(param.tag)].push_back(static_cast<uint8_t>(param.f.integer));
                break;
            case TagType::ULONG:
                map.add(static_cast<uint64_t>(param.tag), param.f.longInteger);
                break;
            case TagType::ULONG_REP:
                uint_repetition[static_cast<uint64_t>(param.tag)].add(param.f.longInteger);
                break;
            case TagType::DATE:
                map.add(static_cast<uint64_t>(param.tag), param.f.dateTime);
                break;
            case TagType::BOOL:
                map.add(static_cast<uint64_t>(param.tag), static_cast<uint8_t>(param.f.boolValue));
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
    if(0 < enum_repetition.size()) {
        for( auto const& [key, val] : enum_repetition ) {
            Bstr bstr(val);
            map.add(key, std::move(bstr));
        }
    }
    if(0 < uint_repetition.size()) {
        for( auto & [key, val] : uint_repetition ) {
            map.add(key, std::move(val));
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
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem)))
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

bool CborConverter::getKeyParameter(const std::pair<const std::unique_ptr<Item>&,
        const std::unique_ptr<Item>&> pair, std::vector<KeyParameter>& keyParams) {
    bool ret = false;
    uint64_t key;
    uint64_t value;

    if(!getUint64(pair.first, key)) {
        return ret;
    }

    /* Get the TagType from the Tag */
    TagType tagType = static_cast<TagType>(key & (0xF << 28));
    switch(tagType) {
        case TagType::ENUM_REP:
            {
                /* ENUM_REP contains values encoded in a Binary string */
                const Bstr* bstr = pair.second.get()->asBstr();
                if(bstr == nullptr) return ret;
                for (auto bchar : bstr->value()) {
                    KeyParameter keyParam;
                    keyParam.tag = static_cast<Tag>(key);
                    keyParam.f.integer = bchar;
                    keyParams.push_back(std::move(keyParam));
                }
                return true;
            }
            break;
        case TagType::ENUM:
        case TagType::UINT:
            {
                KeyParameter keyParam;
                keyParam.tag = static_cast<Tag>(key);
                if(!getUint64(pair.second, value)) {
                    return ret;
                }
                keyParam.f.integer = static_cast<uint32_t>(value);
                keyParams.push_back(std::move(keyParam));
                return true;
            }
            break;
        case TagType::ULONG:
            {
                KeyParameter keyParam;
                keyParam.tag = static_cast<Tag>(key);
                if(!getUint64(pair.second, value)) {
                    return ret;
                }
                keyParam.f.longInteger = value;
                keyParams.push_back(std::move(keyParam));
                return true;
            }
            break;
        case TagType::UINT_REP:
            {
                /* UINT_REP contains values encoded in a Array */
                Array* array = const_cast<Array*>(pair.second.get()->asArray());
                if(array == nullptr) return ret;
                for(int i = 0; i < array->size(); i++) {
                    KeyParameter keyParam;
                    keyParam.tag = static_cast<Tag>(key);
                    std::unique_ptr<Item> item = std::move((*array)[i]);
                    if(!getUint64(item, value)) {
                        return ret;
                    }
                    keyParam.f.integer = static_cast<uint32_t>(value);
                    keyParams.push_back(std::move(keyParam));

                }
                return true;
            }
            break;
        case TagType::ULONG_REP:
            {
                /* ULONG_REP contains values encoded in a Array */
                Array* array = const_cast<Array*>(pair.second.get()->asArray());
                if(array == nullptr) return ret;
                for(int i = 0; i < array->size(); i++) {
                    KeyParameter keyParam;
                    keyParam.tag = static_cast<Tag>(key);
                    std::unique_ptr<Item> item = std::move((*array)[i]);
                    if(!getUint64(item, keyParam.f.longInteger)) {
                        return ret;
                    }
                    keyParams.push_back(std::move(keyParam));

                }
                return true;
            }
            break;
        case TagType::DATE:
            {
                KeyParameter keyParam;
                keyParam.tag = static_cast<Tag>(key);
                if(!getUint64(pair.second, value)) {
                    return ret;
                }
                keyParam.f.dateTime = value;
                keyParams.push_back(std::move(keyParam));
                return true;
            }
            break;
        case TagType::BOOL:
            {
                KeyParameter keyParam;
                keyParam.tag = static_cast<Tag>(key);
                if(!getUint64(pair.second, value)) {
                    return ret;
                }
                keyParam.f.boolValue = static_cast<bool>(value);
                keyParams.push_back(std::move(keyParam));
                return true;
            }
            break;
        case TagType::BYTES:
            {
                KeyParameter keyParam;
                keyParam.tag = static_cast<Tag>(key);
                const Bstr* bstr = pair.second.get()->asBstr();
                if(bstr == nullptr) return ret;
                keyParam.blob = bstr->value();
                keyParams.push_back(std::move(keyParam));
                return true;
            }
            break;
        default:
            /* Invalid skip */
            break;
    }
    return ret;
}


bool CborConverter::getMultiBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
        std::vector<std::vector<uint8_t>>& data) {
    bool ret = false;
    std::unique_ptr<Item> arrayItem(nullptr);

    getItemAtPos(item, pos, arrayItem);
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem)))
        return ret;
    const Array* arr = arrayItem.get()->asArray();
    size_t arrSize = arr->size();
    for (int i = 0; i < arrSize; i++) {
        std::vector<uint8_t> temp;
        if (!getBinaryArray(arrayItem, i, temp))
            return ret;
        data.push_back(std::move(temp));
    }
    ret = true; // success
    return ret;
}

bool CborConverter::getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
        ::android::hardware::hidl_vec<uint8_t>& value) {
    bool ret = false;
    std::unique_ptr<Item> strItem(nullptr);
    getItemAtPos(item, pos, strItem);
    if ((strItem == nullptr) || (MajorType::BSTR != getType(strItem)))
        return ret;

    const Bstr* bstr = strItem.get()->asBstr();
    value = bstr->value();
    ret = true;
    return ret;
}

bool CborConverter::getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
        ::android::hardware::hidl_string& value) {
    std::vector<uint8_t> vec;
    std::string str;
    if(!getBinaryArray(item, pos, vec)) {
        return false;
    }
    for(auto ch : vec) {
        str += ch;
    }
    value = str;
    return true;
}

bool CborConverter::getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<uint8_t>& value) {
    bool ret = false;
    std::unique_ptr<Item> strItem(nullptr);
    getItemAtPos(item, pos, strItem);
    if ((strItem == nullptr) || (MajorType::BSTR != getType(strItem)))
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
    if ((arrayItem == nullptr) || (MajorType::ARRAY != getType(arrayItem)))
        return ret;

    //Seed
    if (!getBinaryArray(arrayItem, 0, params.seed))
        return ret;

    //nonce
    if (!getBinaryArray(arrayItem, 1, paramValue))
        return ret;
    memcpy(params.nonce.data(), paramValue.data(), paramValue.size());
    ret = true;
    return ret;
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

bool CborConverter::getHardwareAuthToken(const std::unique_ptr<Item>& item, const uint32_t pos, HardwareAuthToken& token) {
    bool ret = false;
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
    if (!getBinaryArray(item, pos+5, token.mac))
        return ret;
    ret = true;
    return ret;
}

bool CborConverter::getVerificationToken(const std::unique_ptr<Item>& item, const uint32_t pos, VerificationToken&
        token) {
    bool ret = false;
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
    if (!getBinaryArray(item, pos+4, token.mac))
        return ret;
    ret = true;
    return ret;

}

bool CborConverter::getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos, android::hardware::hidl_vec<KeyParameter>& keyParams) {
    bool ret = false;
    std::unique_ptr<Item> mapItem(nullptr);
    std::vector<KeyParameter> params;
    getItemAtPos(item, pos, mapItem);
    if ((mapItem == nullptr) || (MajorType::MAP != getType(mapItem)))
        return ret;
    const Map* map = mapItem.get()->asMap();
    size_t mapSize = map->size();
    for (int i = 0; i < mapSize; i++) {
        if (!getKeyParameter((*map)[i], params)) {
            return ret;
        }
    }
    keyParams.resize(params.size());
    keyParams = params;
    ret = true;
    return ret;
}
