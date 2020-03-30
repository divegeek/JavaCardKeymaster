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

uint32_t CborConverter::decodeData(const uint8_t *buf, const size_t len, void **ctx) {
    //TODO
}

uint32_t CborConverter::getElement(const void *ctx, const uint32_t index, void **innerCtx) {
    //TODO
}

uint32_t CborConverter::getHmacSharingParameters(const void *ctx,
                                                 std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters> &params) {
    //TODO
}

uint32_t CborConverter::getVerificationTokens(const void *ctx,
                                              std::vector<::android::hardware::keymaster::V4_0::VerificationToken> &tokens) {
    //TODO
}

uint32_t CborConverter::getKeyParameters(const void *ctx,
                                         std::vector<::android::hardware::keymaster::V4_0::KeyParameter> &params) {
    //TODO
}

uint32_t CborConverter::getHardwareAuthTokens(const void *ctx,
                                              std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken> &tokens) {
    //TODO
}

uint32_t CborConverter::getKeyCharacteristics(const void *ctx,
                                              std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics> &keyCharacteristics) {
    //TODO
}

uint32_t CborConverter::getByteArray(const void *ctx, std::vector <uint8_t> &bytes) {
    //TODO
}

uint32_t CborConverter::getUInt64Array(const void *ctx, std::vector <uint64_t> &values) {
    //TODO
}

uint32_t CborConverter::getUInt32Array(const void *ctx, std::vector <uint32_t> &values) {
    //TODO
}

uint32_t CborConverter::encodeHmacSharingParameters(
        const std::vector<::android::hardware::keymaster::V4_0::HmacSharingParameters> &params,
        std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeVerificationTokens(
        const std::vector<::android::hardware::keymaster::V4_0::VerificationToken> &tokens,
        std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeKeyParameters(
        const std::vector<::android::hardware::keymaster::V4_0::KeyParameter> &params,
        std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeHardwareAuthTokens(
        const std::vector<::android::hardware::keymaster::V4_0::HardwareAuthToken> &tokens,
        std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeKeyCharacteristics(
        const std::vector<::android::hardware::keymaster::V4_0::KeyCharacteristics> &keyCharacteristics,
        std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeByteArray(const std::vector <uint8_t> &bytes,
                                        std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeUInt64Array(std::vector <uint64_t> &bytes,
                                          std::vector <uint8_t> &cborData) {
    //TODO
}

uint32_t CborConverter::encodeUInt32Array(std::vector <uint32_t> &bytes,
                                          std::vector <uint8_t> &cborData) {
    //TODO
}

} // namespace V4_1
} // namespace keymaster
} // namespace hardware
} // namespace android