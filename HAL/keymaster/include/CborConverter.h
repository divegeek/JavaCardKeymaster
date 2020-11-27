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

#include <iostream>
#include <numeric>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>

using namespace cppbor;

using ::android::hardware::hidl_vec;
using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using ::android::hardware::keymaster::V4_0::HardwareAuthenticatorType;
using ::android::hardware::keymaster::V4_0::HmacSharingParameters;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::VerificationToken;
using ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using ::android::hardware::keymaster::V4_0::SecurityLevel;
using ::android::hardware::keymaster::V4_0::TagType;
using ::android::hardware::keymaster::V4_0::Tag;

class CborConverter
{
    public:
        CborConverter() = default;
        ~CborConverter() = default;

        /**
         * Parses the input data which is in CBOR format and returns a Tuple of Item pointer and the first element in the item pointer.          
         */
        template<typename T = ErrorCode>
        std::tuple<std::unique_ptr<Item>, T> decodeData(const std::vector<uint8_t>& response, bool
                hasErrorCode) {
            const uint8_t* pos;
            std::unique_ptr<Item> item(nullptr);
            std::string message;
            T errorCode = T::OK;

            std::tie(item, pos, message) = parse(response);

            if(item != nullptr && hasErrorCode) {
                if(MajorType::ARRAY == getType(item)) {
                    if(!getErrorCode(item, 0, errorCode))
                        item = nullptr;
                } else if (MajorType::UINT == getType(item)) {
                    uint64_t err;
                    if(getUint64(item, err)) {
                        errorCode = static_cast<T>(get2sCompliment(static_cast<uint32_t>(err)));
                    }
                    item = nullptr; /*Already read the errorCode. So no need of sending item to client */
                }
            }
            return {std::move(item), errorCode};
        }

        /**
         * Get the signed/unsigned integer value at a given position from the item pointer.
         */
        template<typename T>
        bool getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value);

        /**
         * Get the signed/unsigned integer value from the item pointer.
         */
        template<typename T>
        bool getUint64(const std::unique_ptr<Item>& item, T& value);

        /**
         * Get the HmacSharingParameters structure value at the given position from the item pointer.
         */
        bool getHmacSharingParameters(const std::unique_ptr<Item>& item, const uint32_t pos, HmacSharingParameters& params);

        /**
         * Get the Binary string at the given position from the item pointer.
         */
        bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, ::android::hardware::hidl_string& value);

        /**
         * Get the Binary string at the given position from the item pointer.
         */
        bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<uint8_t>& value);

        /**
         * Get the Binary string at the given position from the item pointer.
         */
        bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
                ::android::hardware::hidl_vec<uint8_t>& value);
        /**
         * Get the HardwareAuthToken value at the given position from the item pointer.
         */
        bool getHardwareAuthToken(const std::unique_ptr<Item>& item, const uint32_t pos, HardwareAuthToken& authType);

        /**
         * Get the list of KeyParameters value at the given position from the item pointer.
         */
        bool getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos, android::hardware::hidl_vec<KeyParameter>& keyParams);

        /**
         * Adds the the list of KeyParameters values to the Array item.
         */
        bool addKeyparameters(Array& array, const android::hardware::hidl_vec<KeyParameter>&
                keyParams);

        /**
         * Add HardwareAuthToken value to the Array item.
         */
        bool addHardwareAuthToken(Array& array, const HardwareAuthToken&
                authToken);

        /**
         * Get the VerificationToken value at the given position from the item pointer.
         */
        bool getVerificationToken(const std::unique_ptr<Item>& item, const uint32_t pos, VerificationToken&
                token);

        /**
         * Get the KeyCharacteristics value at the given position from the item pointer.
         */
        bool getKeyCharacteristics(const std::unique_ptr<Item> &item, const uint32_t pos,
                KeyCharacteristics& keyCharacteristics);

        /**
         * Get the list of binary arrays at the given position from the item pointer.
         */
        bool getMultiBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos,
                std::vector<std::vector<uint8_t>>& data);

        /**
         * Add VerificationToken value to the Array item.
         */
        bool addVerificationToken(Array& array, const VerificationToken&
                verificationToken, std::vector<uint8_t>& encodedParamsVerified);

        /**
         * Get the ErrorCode value at the give position from the item pointer.
         */
        template<typename T, typename = std::enable_if_t<(std::is_same_v<T, ErrorCode>) ||
            (std::is_same_v<T, ::android::hardware::keymaster::V4_1::ErrorCode>)>>
            inline bool getErrorCode(const std::unique_ptr<Item>& item, const uint32_t pos, T& errorCode) {
                bool ret = false;
                uint64_t errorVal;
                if (!getUint64<uint64_t>(item, pos, errorVal)) {
                    return ret;
                }
                errorCode = static_cast<T>(get2sCompliment(static_cast<uint32_t>(errorVal)));

                ret = true;
                return ret;
            }

    private:
        /**
         * Returns the negative value of the same number.
         */
        inline int32_t get2sCompliment(uint32_t value) { return static_cast<int32_t>(~value+1); }

        /**
         * Get the type of the Item pointer.
         */
        inline MajorType getType(const std::unique_ptr<Item> &item) { return item.get()->type(); }

        /**
         * Construct Keyparameter structure from the pair of key and value. If TagType is  ENUM_REP the value contains
         * binary string. If TagType is UINT_REP or ULONG_REP the value contains Array of unsigned integers.
         */
        bool getKeyParameter(const std::pair<const std::unique_ptr<Item>&,
                const std::unique_ptr<Item>&> pair, std::vector<KeyParameter>& keyParam);

        /**
         * Get the sub item pointer from the root item pointer at the given position.
         */
        inline void getItemAtPos(const std::unique_ptr<Item>& item, const uint32_t pos, std::unique_ptr<Item>& subItem) {
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

template<typename T>
bool CborConverter::getUint64(const std::unique_ptr<Item>& item, T& value) {
    bool ret = false;
    if ((item == nullptr) ||
            (std::is_unsigned<T>::value && (MajorType::UINT != getType(item))) ||
            ((std::is_signed<T>::value && (MajorType::NINT != getType(item))))) {
        return ret;
    }

    if (std::is_unsigned<T>::value) {
        const Uint* uintVal = item.get()->asUint();
        value = uintVal->value();
    }
    else {
        const Nint* nintVal = item.get()->asNint();
        value = nintVal->value();
    }
    ret = true;
    return ret; //success
}

template<typename T>
bool CborConverter::getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value) {
    std::unique_ptr<Item> intItem(nullptr);
    getItemAtPos(item, pos, intItem);
    return getUint64(intItem, value);
}



#endif
