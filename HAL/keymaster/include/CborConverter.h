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

#ifndef __CBOR_CONVERTER_H_
#define __CBOR_CONVERTER_H_
#include <sstream>
#include <iostream>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <numeric>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>

#define EMPTY(A) *(A*)nullptr

using namespace cppbor;

using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::HardwareAuthenticatorType;
using ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using ::android::hardware::keymaster::V4_0::HmacSharingParameters;
using ::android::hardware::keymaster::V4_0::IKeymasterDevice;
using ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using ::android::hardware::keymaster::V4_0::KeyFormat;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::KeyPurpose;
using ::android::hardware::keymaster::V4_0::SecurityLevel;
using ::android::hardware::keymaster::V4_0::Tag;
using ::android::hardware::keymaster::V4_0::VerificationToken;

class CborConverter
{
    public:
        CborConverter() = default;
        ~CborConverter() = default;

        ParseResult decodeData(const std::vector<uint8_t> cborData);

        /* Use this function to get both signed and usinged integers.*/
        template<typename T>
            bool getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value);
        bool getHmacSharingParameters(const std::unique_ptr<Item>& item, const uint32_t pos, HmacSharingParameters& params);
        bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<uint8_t>& vec);
        bool getHardwareAuthToken(const std::unique_ptr<Item>& item, const uint32_t pos, HardwareAuthToken& authType);
        bool getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos, android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams);
        bool addKeyparameters(Array& array, const android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>&
                keyParams);
        bool addHardwareAuthToken(Array& array, const ::android::hardware::keymaster::V4_0::HardwareAuthToken&
                authToken);
        bool getVerificationToken(const std::unique_ptr<Item>& item, const uint32_t pos, VerificationToken&
                token);
        bool getKeyCharacteristics(const std::unique_ptr<Item> &item, const uint32_t pos,
                ::android::hardware::keymaster::V4_0::KeyCharacteristics& keyCharacteristics);
        bool getMultiBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
                ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>>& data);
        bool addVerificationToken(Array& array, const ::android::hardware::keymaster::V4_0::VerificationToken&
                verificationToken);

        template<typename T, typename = std::enable_if_t<(std::is_same_v<T, ::android::hardware::keymaster::V4_0::ErrorCode>) ||
            (std::is_same_v<T, ::android::hardware::keymaster::V4_1::ErrorCode>)>>
            inline bool getErrorCode(const std::unique_ptr<Item>& item, const uint32_t pos, T& errorCode) {
                bool ret = false;
                uint64_t errorVal;
                if (!getUint64<uint64_t>(item, pos, errorVal)) {
                    return ret;
                }
                errorCode = static_cast<T>(errorVal);

                ret = true;
                return ret;
            }




    private:
        inline MajorType getType(const std::unique_ptr<Item> &item) { return item.get()->type(); }
        bool getKeyparameter(const std::pair<const std::unique_ptr<Item>&,
                const std::unique_ptr<Item>&> pair, KeyParameter& keyParam);
        inline const std::unique_ptr<Item>& getItemAtPos(const std::unique_ptr<Item>& item, const uint32_t pos) {
            const Array* arr = nullptr;

            if (MajorType::ARRAY != getType(item)) {
                return EMPTY(std::unique_ptr<Item>);
            }
            arr = item.get()->asArray();
            if (arr->size() < (pos + 1)) {
                return EMPTY(std::unique_ptr<Item>);
            }
            return (*arr)[pos];
        }
};

template<typename T>
bool CborConverter::getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value) {
    bool ret = false;
    const std::unique_ptr<Item>& intItem = getItemAtPos(item, pos);

    if ((intItem == nullptr) ||
            (std::is_unsigned<T>::value && (MajorType::UINT != getType(intItem))) ||
            ((std::is_signed<T>::value && (MajorType::NINT != getType(intItem))))) {
        return ret;
    }

    if (std::is_unsigned<T>::value) {
        const Uint* uintVal = intItem.get()->asUint();
        value = uintVal->value();
    }
    else {
        const Nint* nintVal = intItem.get()->asNint();
        value = nintVal->value();
    }
    ret = true;
    return ret; //success
}

#endif
