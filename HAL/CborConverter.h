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
#pragma once
#include <aidl/android/hardware/security/keymint/Certificate.h>
#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>
#include <aidl/android/hardware/security/sharedsecret/ISharedSecret.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <iostream>
#include <keymaster/android_keymaster_messages.h>
#include <memory>
#include <numeric>
#include <vector>

namespace keymint::javacard {
using namespace cppbor;
using namespace aidl::android::hardware::security::keymint;
using namespace aidl::android::hardware::security::secureclock;
using namespace aidl::android::hardware::security::sharedsecret;
using std::string;
using std::unique_ptr;
using std::vector;

class CborConverter {
  public:
    CborConverter() = default;
    ~CborConverter() = default;
    std::tuple<std::unique_ptr<Item>, keymaster_error_t>
    decodeData(const std::vector<uint8_t>& response);

    template <typename T>
    bool getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value);

    template <typename T> bool getUint64(const std::unique_ptr<Item>& item, T& value);

    bool getSharedSecretParameters(const std::unique_ptr<Item>& item, const uint32_t pos,
                                   SharedSecretParameters& params);
    bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, string& value);

    bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
                        vector<uint8_t>& value);

    bool getHardwareAuthToken(const std::unique_ptr<Item>& item, const uint32_t pos,
                              HardwareAuthToken& authType);

    bool getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos,
                          vector<KeyParameter>& keyParams);

    bool addKeyparameters(Array& array, const vector<KeyParameter>& keyParams);

    bool addAttestationKey(Array& array, const std::optional<AttestationKey>& attestationKey);

    bool addHardwareAuthToken(Array& array, const HardwareAuthToken& authToken);

    bool addSharedSecretParameters(Array& array, const vector<SharedSecretParameters>& params);

    bool getTimeStampToken(const std::unique_ptr<Item>& item, const uint32_t pos,
                           TimeStampToken& token);

    bool getKeyCharacteristics(const std::unique_ptr<Item>& item, const uint32_t pos,
                               vector<KeyCharacteristics>& keyCharacteristics);

    bool getCertificateChain(const std::unique_ptr<Item>& item, const uint32_t pos,
                             vector<Certificate>& keyCharacteristics);

    bool getMultiBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
                             vector<vector<uint8_t>>& data);

    bool addTimeStampToken(Array& array, const TimeStampToken& token);

    bool getMapItem(const std::unique_ptr<Item>& item, const uint32_t pos,
                             Map& map);
    
    bool getArrayItem(const std::unique_ptr<Item>& item, const uint32_t pos,
                             Array& array);

    inline bool getErrorCode(const std::unique_ptr<Item>& item, const uint32_t pos,
                             keymaster_error_t& errorCode) {
        uint64_t errorVal;
        if (!getUint64<uint64_t>(item, pos, errorVal)) {
            return false;
        }
        errorCode = static_cast<keymaster_error_t>(0 - errorVal);
        return true;
    }

  private:
    /**
     * Returns the negative value of the same number.
     */
    inline int32_t get2sCompliment(uint32_t value) { return static_cast<int32_t>(~value + 1); }

    /**
     * Get the type of the Item pointer.
     */
    inline MajorType getType(const unique_ptr<Item>& item) { return item.get()->type(); }

    /**
     * Construct Keyparameter structure from the pair of key and value. If TagType is  ENUM_REP the
     * value contains binary string. If TagType is UINT_REP or ULONG_REP the value contains Array of
     * unsigned integers.
     */
    bool getKeyParameter(const std::pair<const unique_ptr<Item>&, const unique_ptr<Item>&> pair,
                         vector<KeyParameter>& keyParam);

    /**
     * Get the sub item pointer from the root item pointer at the given position.
     */
    inline void getItemAtPos(const unique_ptr<Item>& item, const uint32_t pos,
                             unique_ptr<Item>& subItem) {
        Array* arr = nullptr;

        if (MajorType::ARRAY != getType(item)) {
            return;
        }
        arr = const_cast<Array*>(item.get()->asArray());
        if (arr->size() < (pos + 1)) {
            return;
        }
        subItem = std::move((*arr)[pos]);
    }
};

template <typename T> bool CborConverter::getUint64(const unique_ptr<Item>& item, T& value) {
    bool ret = false;
    if ((item == nullptr) || (std::is_unsigned<T>::value && (MajorType::UINT != getType(item))) ||
        ((std::is_signed<T>::value && (MajorType::NINT != getType(item))))) {
        return ret;
    }

    if (std::is_unsigned<T>::value) {
        const Uint* uintVal = item.get()->asUint();
        value = static_cast<T>(uintVal->value());
    } else {
        const Nint* nintVal = item.get()->asNint();
        value = static_cast<T>(nintVal->value());
    }
    ret = true;
    return ret;  // success
}

template <typename T>
bool CborConverter::getUint64(const unique_ptr<Item>& item, const uint32_t pos, T& value) {
    unique_ptr<Item> intItem(nullptr);
    getItemAtPos(item, pos, intItem);
    return getUint64(intItem, value);
}
}  // namespace keymint::javacard
