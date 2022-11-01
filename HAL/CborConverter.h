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

#include <iostream>
#include <memory>
#include <numeric>
#include <vector>

#include <cppbor.h>
#include <cppbor_parse.h>

#include <aidl/android/hardware/security/keymint/Certificate.h>
#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <aidl/android/hardware/security/sharedsecret/ISharedSecret.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>

#include <keymaster/android_keymaster_messages.h>

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
    std::optional<T> getUint64(const unique_ptr<Item> &item) {
        T value;
        if ((item == nullptr) || (std::is_unsigned<T>::value && (MajorType::UINT != getType(item))) ||
            ((std::is_signed<T>::value && (MajorType::NINT != getType(item))))) {
            return std::nullopt;
        }
        if (std::is_unsigned<T>::value) {
            const Uint *uintVal = item.get()->asUint();
            value = static_cast<T>(uintVal->value());
        } else {
            const Nint *nintVal = item.get()->asNint();
            value = static_cast<T>(nintVal->value());
        }
        return value; // success
    }

    template <typename T>
    std::optional<T> getUint64(const unique_ptr<Item> &item, const uint32_t pos) {
        auto intItem = getItemAtPos(item, pos);
        return getUint64<T>(intItem.value());
    }

    std::optional<SharedSecretParameters> getSharedSecretParameters(const std::unique_ptr<Item>& item, const uint32_t pos);
    
    std::optional<string> getByteArrayStr(const unique_ptr<Item>& item, const uint32_t pos);
    
    std::optional<string> getTextStr(const unique_ptr<Item>& item, const uint32_t pos);

    std::optional<std::vector<uint8_t>> getByteArrayVec(const unique_ptr<Item>& item, const uint32_t pos);

    std::optional<vector<KeyParameter>> getKeyParameters(const unique_ptr<Item>& item, const uint32_t pos);

    bool addKeyparameters(Array& array, const vector<KeyParameter>& keyParams);

    bool addAttestationKey(Array& array, const std::optional<AttestationKey>& attestationKey);

    bool addHardwareAuthToken(Array& array, const HardwareAuthToken& authToken);

    bool addSharedSecretParameters(Array& array, const vector<SharedSecretParameters>& params);

    std::optional<TimeStampToken> getTimeStampToken(const std::unique_ptr<Item>& item, const uint32_t pos);

    std::optional<vector<KeyCharacteristics>> getKeyCharacteristics(const std::unique_ptr<Item>& item, const uint32_t pos);

    std::optional<vector<Certificate>> getCertificateChain(const std::unique_ptr<Item>& item, const uint32_t pos);

    std::optional<vector<vector<uint8_t>>> getMultiByteArray(const unique_ptr<Item>& item, const uint32_t pos);

    bool addTimeStampToken(Array& array, const TimeStampToken& token);

    std::optional<Map> getMapItem(const std::unique_ptr<Item>& item, const uint32_t pos);
    
    std::optional<Array> getArrayItem(const std::unique_ptr<Item>& item, const uint32_t pos);

    inline std::optional<keymaster_error_t> getErrorCode(const std::unique_ptr<Item>& item, const uint32_t pos) {

        auto optErrorVal = getUint64<uint64_t>(item, pos);
        if (!optErrorVal) {
            return std::nullopt;
        }
        return static_cast<keymaster_error_t>(0 - optErrorVal.value());
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
    std::optional<std::vector<KeyParameter>>
        getKeyParameter(const std::pair<const std::unique_ptr<Item>&,
                const std::unique_ptr<Item>&> pair);

    /**
     * Get the sub item pointer from the root item pointer at the given position.
     */
    inline std::optional<unique_ptr<Item>> getItemAtPos(const unique_ptr<Item>& item, const uint32_t pos) {
        Array* arr = nullptr;

        if (MajorType::ARRAY != getType(item)) {
            return std::nullopt;
        }
        arr = const_cast<Array*>(item.get()->asArray());
        if (arr->size() < (pos + 1)) {
            return std::nullopt;
        }
        return std::move((*arr)[pos]);
    }
};

}  // namespace keymint::javacard
