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
#include <numeric>

#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#include <hidl/HidlSupport.h>

#include <cppbor.h>
#include <cppbor_parse.h>

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
        std::tuple<std::unique_ptr<cppbor::Item>, ErrorCode> decodeData(const std::vector<uint8_t>& response,
                                                                        bool hasErrorCode);

        /**
         * Get the unsigned integer value from the item pointer.
         */
        std::optional<uint64_t> getUint64(const std::unique_ptr<cppbor::Item> &item);

        /**
         * Get the unsigned integer value at a given position from the item pointer.
         */
        std::optional<uint64_t> getUint64(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Get the HmacSharingParameters structure value at the given position from the item pointer.
         */
        std::optional<HmacSharingParameters> getHmacSharingParameters(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Get the Binary string at the given position from the item pointer.
         */
        std::optional<::android::hardware::hidl_string> getByteArrayHidlStr(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Get the Binary string at the given position from the item pointer.
         */
        std::optional<std::vector<uint8_t>> getByteArrayVec(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Get the Binary string at the given position from the item pointer.
         */
        std::optional<::android::hardware::hidl_vec<uint8_t>> getByteArrayHidlVec(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Get the list of KeyParameters value at the given position from the item pointer.
         */
        std::optional<android::hardware::hidl_vec<KeyParameter>> getKeyParameters(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Adds the the list of KeyParameters values to the Array item.
         */
        bool addKeyparameters(cppbor::Array& array, const android::hardware::hidl_vec<KeyParameter>&
                keyParams);

        /**
         * Add HardwareAuthToken value to the Array item.
         */
        bool addHardwareAuthToken(cppbor::Array& array, const HardwareAuthToken&
                authToken);


        /**
         * Get the KeyCharacteristics value at the given position from the item pointer.
         */
        std::optional<KeyCharacteristics> getKeyCharacteristics(const std::unique_ptr<cppbor::Item> &item, const uint32_t pos);

        /**
         * Get the list of binary arrays at the given position from the item pointer.
         */
        std::optional<std::vector<std::vector<uint8_t>>> getCertChain(const std::unique_ptr<cppbor::Item>& item, const uint32_t pos);

        /**
         * Add VerificationToken value to the Array item.
         */
        bool addVerificationToken(cppbor::Array& array, const VerificationToken&
                verificationToken, std::vector<uint8_t>& encodedParamsVerified);

        /**
         * Get the ErrorCode value at the give position from the item pointer.
         */
        std::optional<ErrorCode> getErrorCode(const std::unique_ptr<cppbor::Item> &item, const uint32_t pos);

    private:
        /**
         * Get the type of the Item pointer.
         */
        inline cppbor::MajorType getType(const std::unique_ptr<cppbor::Item> &item) { return item.get()->type(); }

        /**
         * Construct Keyparameter structure from the pair of key and value. If TagType is  ENUM_REP the value contains
         * binary string. If TagType is UINT_REP or ULONG_REP the value contains Array of unsigned integers.
         */
        std::optional<std::vector<KeyParameter>> getKeyParameter(const std::pair<const std::unique_ptr<cppbor::Item>&,
                const std::unique_ptr<cppbor::Item>&> pair);

        /** 
         * Checks if the item is of type Array and the pos is not out of range.
         */
        std::optional<std::unique_ptr<cppbor::Item>> getItemAtPos(const std::unique_ptr<cppbor::Item> &item, const uint32_t pos);
};
