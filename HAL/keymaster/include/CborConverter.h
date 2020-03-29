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
         * Converts from Cbor format to array of HmacSharingParameters structures.
         * @param[in] buf The array of bytes to convert.
         * @param[in] len The number of bytes in the array.
         * @param[out] params The parsed array of HmacSharingParameters structure.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeHmacSharingParameters(const uint8_t *buf, const size_t len, std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params);

         /**
          * Converts from array of HmacSharingParameters structures to Cbor format.
          * @param[in] params Array of HmacSharingParameters instances to be encoded.
          * @param[out] buf Encoded byte array.
          * @param[out] len The number of bytes in the encoded array.
          * @return 0 if success, or error code if failure.
          */
        uint32_t encodeHmacSharingParameters(std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params, uint8_t **buf, size_t *len);

        /**
         * Converts Cbor format to array of VerificationToken structures.
         * @param[in] buf The array of bytes to convert.
         * @param[in] len The number of bytes in the array.
         * @param[out] tokens The parsed array of VerificationToken structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeVerificationTokens(const uint8_t *buf, const size_t len, std::vector<::android::hardware::keymaster::V4_0::VerificationToken>& tokens);

        /**
         * Converts from array of VerificationToken structures to Cbor format.
         * @param[in] tokens Array of VerificationToken instances to be encoded.
         * @param[out] buf Encoded byte array.
         * @param[out] len The number of bytes in the encoded array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeVerificationTokens(const std::vector<::android::hardware::keymaster::V4_0::VerificationToken>& tokens, uint8_t **buf, size_t *len);

        /**
         * Converts Cbor format to array of KeyParameter structures.
         * @param[in] buf The array of bytes to convert.
         * @param[in] len The number of bytes in the array.
         * @param[out] params The parsed array of KeyParameter structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeKeyParameters(const uint8_t *buf, const size_t len, std::vector<::android::hardware::keymaster::V4_0::KeyParameter>& params);

        /**
         * Converts from array of KeyParameter structures to Cbor format.
         * @param[in] params Array of KeyParameter instances to be encoded.
         * @param[out] buf Encoded byte array.
         * @param[out] len The number of bytes in the encoded array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeKeyParameters(const std::vector<::android::hardware::keymaster::V4_0::KeyParameter>& params, uint8_t **buf, size_t *len);

        /**
         * Converts Cbor format to array of HardwareAuthToken structures.
         * @param[in] buf The array of bytes to convert.
         * @param[in] len The number of bytes in the array.
         * @param[out] tokens The parsed HardwareAuthToken structure.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeHardwareAuthTokens(const uint8_t *buf, const size_t len, std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken>& tokens);

        /**
         * Converts from array of HardwareAuthToken structures to Cbor format.
         * @param[in] tokens Array of HardwareAuthToken instances to be encoded.
         * @param[out] buf Encoded byte array.
         * @param[out] len The number of bytes in the encoded array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeHardwareAuthTokens(const std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken>& tokens, uint8_t **buf, size_t *len);

        /**
         * Converts Cbor format to array of keyCharacteristics structures.
         * @param[in] buf The array of bytes to convert.
         * @param[in] len The number of bytes in the array.
         * @param[out] keyCharacteristics The parsed array of keyCharacteristics structures.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeKeyCharacteristics(const uint8_t *buf, const size_t len, std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics>& keyCharacteristics);

        /**
         * Converts from array of KeyCharacteristics structures to Cbor format.
         * @param[in] keyCharacteristics Array of KeyCharacteristics instances to be encoded.
         * @param[out] buf Encoded byte array.
         * @param[out] len The number of bytes in the encoded array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeKeyCharacteristics(const std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics>& keyCharacteristics, uint8_t **buf, size_t *len);

        /**
         * Converts Cbor format to vector array.
         * @param[in] buf The array of bytes to convert.
         * @param[in] len The number of bytes in the array.
         * @param[out] bytes The parsed vector array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t decodeByteArray(const uint8_t *buf, const size_t len, std::vector<uint8_t>& bytes);

        /**
         * Converts from vector array to Cbor format.
         * @param[in] bytes vector array instance to be encoded.
         * @param[out] buf Encoded byte array.
         * @param[out] len The number of bytes in the encoded array.
         * @return 0 if success, or error code if failure.
         */
        uint32_t encodeByteArray(const std::vector<uint8_t>& bytes, uint8_t **buf, size_t *len);

};

} // namespace V4_1
} // namespace keymaster
} // namespace hardware
} // namespace android

#endif //ANDROID_HARDWARE_KEYMASTER_V4_1_CBORCONVERTER_H
