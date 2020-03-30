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

#ifndef ANDROID_HARDWARE_KEYMASTER_V4_1_CBORCONVERTER_H
#define ANDROID_HARDWARE_KEYMASTER_V4_1_CBORCONVERTER_H

namespace android {
namespace hardware {
namespace keymaster {
namespace V4_1 {

class CborConverter {
    public:
        CborConverter();

        virtual ~CborConverter();

        //Conversion methods
        /**
         * Decodes the CBOR data and returns a context. This context
         * has to be passed to each API for retrieving individual elements.
         * @param[in] buf The array of bytes to decode.
         * @param[in] len The number of bytes in the array.
         * @param[out] ctx Data structure formed from parsed CBOR data.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeData(const uint8_t *buf, const size_t len, void **ctx);

        /**
         * Get an element at index from the main context.
         * @param[in] ctx Data structure pointer returned from @ref decodeData(const uint8_t, const size_t, void**).
         * @param[in] index The position where to retrieve the element from.
         * @param[out] innerCtx Data structure corresponding to the element at index.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getElement(const void *ctx, const uint32_t index, void **innerCtx);

        /**
         * Retrieves the array of HmacSharingParameters.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] params The array of HmacSharingParameters.
         * @return  0 if success, or error code if failure.
         */
        uint32_t getHmacSharingParameters(const void *ctx, std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params);

        /**
         * Converts from array of HmacSharingParameters structures to Cbor format.
         * @param[in] params Array of HmacSharingParameters instances to be encoded.
         * @param[out] cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeHmacSharingParameters(const std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params, std::vector<uint8_t>& cborData);

        /**
         * Retrieves the array of VerificationTokens.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] tokens The array of VerificationToken structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getVerificationTokens(const void *ctx, std::vector<::android::hardware::keymaster::V4_0::VerificationToken>& tokens);

        /**
         * Converts from array of VerificationToken structures to Cbor format.
         * @param[in] tokens Array of VerificationToken instances to be encoded.
         * @param[out] cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeVerificationTokens(const std::vector<::android::hardware::keymaster::V4_0::VerificationToken>& tokens, std::vector<uint8_t>& cborData);

        /**
         * Retrieves the array of KeyParameter structures.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] params The array of KeyParameter structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getKeyParameters(const void *ctx, std::vector<::android::hardware::keymaster::V4_0::KeyParameter>& params);

        /**
         * Converts from array of KeyParameter structures to Cbor format.
         * @param[in] params Array of KeyParameter instances to be encoded.
         * @param[out] cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeKeyParameters(const std::vector<::android::hardware::keymaster::V4_0::KeyParameter>& params, std::vector<uint8_t>& cborData);

        /**
         * Retrieves the array of HardwareAuthToken structures.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] tokens The array of HardwareAuthToken structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getHardwareAuthTokens(const void *ctx, std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken>& tokens);

        /**
         * Converts from array of HardwareAuthToken structures to Cbor format.
         * @param[in] tokens Array of HardwareAuthToken instances to be encoded.
         * @param[out] cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeHardwareAuthTokens(const std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken>& tokens, std::vector<uint8_t>& cborData);

        /**
         * Retrieves the array of keyCharacteristics structures.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] keyCharacteristics The array of keyCharacteristics structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getKeyCharacteristics(const void *ctx, std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics>& keyCharacteristics);

        /**
         * Converts from array of KeyCharacteristics structures to Cbor format.
         * @param[in] keyCharacteristics Array of KeyCharacteristics instances to be encoded.
         * @param[out] cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeKeyCharacteristics(const std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics>& keyCharacteristics, std::vector<uint8_t>& cborData);

        /**
         * Retrieves byte array.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] bytes The parsed byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getByteArray(const void *ctx, std::vector<uint8_t>& bytes);

        /**
         * Converts from vector array to Cbor format.
         * @param[in] bytes Byte array instance to be encoded.
         * @param[out] cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeByteArray(const std::vector<uint8_t>& bytes, std::vector<uint8_t>& cborData);

        /**
         * Retrieves uint64_t array.
         * @param[in] ctx Data structure context corresponding to this element.
         * @param[out] values The parsed uint64_t array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getUInt64Array(const void *ctx, std::vector<uint64_t>& values);

        /**
         * Retrieves uint32_t array.
         * @param[in]  ctx Data structure context corresponding to this element.
         * @param[out] values The parsed uint32_t array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t getUInt32Array(const void *ctx, std::vector<uint32_t>& values);

        /**
         * Converts from uint64_t array to Cbor format.
         * @param bytes uint64_t array to be encoded.
         * @param cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeUInt64Array(std::vector<uint64_t> &bytes, std::vector<uint8_t>& cborData);

        /**
         * Converts from uint32_t array to Cbor format.
         * @param bytes uint64_t array to be encoded.
         * @param cborData Encoded byte array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeUInt32Array(std::vector<uint32_t> &bytes, std::vector<uint8_t>& cborData);
};

} // namespace V4_1
} // namespace keymaster
} // namespace hardware
} // namespace android

#endif //ANDROID_HARDWARE_KEYMASTER_V4_1_CBORCONVERTER_H
