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

namespace android {
namespace hardware {
namespace keymaster {
namespace V4_1 {

CborConverter::CborConverter() {
//TODO
}

CborConverter::~CborConverter() {
//TODO
}

uint32_t CborConverter::decodeHardwareAuthTokens(const uint8_t *buf, const size_t len,
                                                 std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken> &tokens) {
    //TODO
}

uint32_t CborConverter::encodeHardwareAuthTokens(
        const std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken> &tokens,
        uint8_t **buf, size_t *len) {
    //TODO
}

uint32_t CborConverter::decodeHmacSharingParameters(const uint8_t *buf, const size_t len,
                                                    std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters> &params) {
    //TODO
}

uint32_t CborConverter::encodeHmacSharingParameters(
        std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters> &params,
        uint8_t **buf, size_t *len) {
    //TODO
}

uint32_t CborConverter::encodeKeyCharacteristics(
        const std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics> &keyCharacteristics,
        uint8_t **buf, size_t *len) {
    //TODO
}

uint32_t CborConverter::decodeKeyCharacteristics(const uint8_t *buf, const size_t len,
                                                 std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics> &keyCharacteristics) {
    //TODO
}

uint32_t CborConverter::encodeKeyParameters(
        const std::vector<::android::hardware::keymaster::V4_0::KeyParameter> &params,
        uint8_t **buf, size_t *len) {
    //TODO
}

uint32_t CborConverter::decodeKeyParameters(const uint8_t *buf, const size_t len,
                                            std::vector<::android::hardware::keymaster::V4_0::KeyParameter> &params) {
    //TODO
}

uint32_t CborConverter::encodeVerificationTokens(
        const std::vector<::android::hardware::keymaster::V4_0::VerificationToken> &tokens,
        uint8_t **buf, size_t *len) {
    //TODO
}

uint32_t CborConverter::decodeVerificationTokens(const uint8_t *buf, const size_t len,
                                                 std::vector<::android::hardware::keymaster::V4_0::VerificationToken> &tokens) {
    //TODO
}

uint32_t CborConverter::encodeByteArray(const std::vector <uint8_t> &bytes, uint8_t **buf,
                                        size_t *len) {
    //TODO
}

uint32_t CborConverter::decodeByteArray(const uint8_t *buf, const size_t len,
                                        std::vector <uint8_t> &bytes) {
    //TODO
}

} // namespace V4_1
} // namespace keymaster
} // namespace hardware
} // namespace android
