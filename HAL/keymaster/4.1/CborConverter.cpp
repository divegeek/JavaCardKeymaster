#pragma
#include <sstream>
#include <iostream>
#include <cppbor.h>
#include <cppbor_parse.h>
#include "CborConverter.h"
using namespace cppbor;

HardwareAuthenticatorType convertToHardwareAuthenticatorType(uint64_t val) {
    switch (static_cast<HardwareAuthenticatorType>(val)) {
    case HardwareAuthenticatorType::NONE: 
        return HardwareAuthenticatorType::NONE;
    case HardwareAuthenticatorType::PASSWORD:
        return HardwareAuthenticatorType::PASSWORD;
    case HardwareAuthenticatorType::FINGERPRINT:
        return HardwareAuthenticatorType::FINGERPRINT;
    case HardwareAuthenticatorType::ANY:
        return HardwareAuthenticatorType::ANY;
    }
}

bool convertToTag(uint64_t val, TAG& tag) {
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
}

bool getTagValue(TAG& tag, KeyParameter& keyParam, uint64_t& value) {
    return false;
}

bool CborConverter::getKeyparameter(const std::pair<const std::unique_ptr<Item>&,
    const std::unique_ptr<Item>&> pair, KeyParameter& keyParam) {
    bool ret = false;
    KeyParameter::IntegerParams p;
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
        if (!getBinaryArray(pair.second, 0, keyParam.blob)) {
            return ret;
        }
    }
    else {
        return ret;
    }
}

ParseResult CborConverter::decodeData(const std::vector<uint8_t> cborData) {
    const uint8_t* pos;
    std::unique_ptr<Item> item;
    std::string message;
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
    std::vector<uint8_t> nonce;
    bool ret = false;
    //Seed
    if (!getBinaryArray(item, pos, params.seed))
        return ret;
    //nonce
    if (!getBinaryArray(item, pos+1, nonce))
        return ret;
    std::copy(nonce.begin(), nonce.end(), params.nonce);
    ret = true;
    return ret;
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
    token.authType = convertToHardwareAuthenticatorType(authType);
    //Timestamp
    if (!getUint64<uint64_t>(item, pos+4, token.timestamp))
        return ret;
    if (!getBinaryArray(item, pos + 5, token.mac))
        return ret;
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

