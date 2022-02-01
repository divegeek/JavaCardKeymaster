/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "javacard.strongbox.keymint.operation-impl"

#include "JavacardKeyMintOperation.h"
#include <JavacardKeyMintUtils.h>
#include <KeyMintUtils.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>
#include <android-base/logging.h>

namespace aidl::android::hardware::security::keymint {
using namespace ::keymaster;
using secureclock::TimeStampToken;
using std::nullopt;

ScopedAStatus JavacardKeyMintOperation::updateAad(const vector<uint8_t>& input,
                                                  const optional<HardwareAuthToken>& authToken,
                                                  const optional<TimeStampToken>& timestampToken) {
    ::keymaster::HardwareAuthToken legacyToken;
    vector<uint8_t> encodedTimestampToken;
    HardwareAuthToken aToken = authToken.value_or(HardwareAuthToken());
    TimeStampToken tToken = timestampToken.value_or(TimeStampToken());
    legacyHardwareAuthToken(aToken, &legacyToken);
    encodeTimestampToken(tToken, &encodedTimestampToken);
    auto err = jcKmOprImpl_->updateAad(input, legacyToken, encodedTimestampToken);
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintOperation::update(const vector<uint8_t>& input,
                                               const optional<HardwareAuthToken>& authToken,
                                               const optional<TimeStampToken>& timestampToken,
                                               vector<uint8_t>* output) {
    ::keymaster::HardwareAuthToken legacyToken;
    vector<uint8_t> encodedTimestampToken;
    HardwareAuthToken aToken = authToken.value_or(HardwareAuthToken());
    TimeStampToken tToken = timestampToken.value_or(TimeStampToken());
    legacyHardwareAuthToken(aToken, &legacyToken);
    encodeTimestampToken(tToken, &encodedTimestampToken);
    auto err = jcKmOprImpl_->update(input, nullopt, legacyToken, encodedTimestampToken, nullptr,
                                    nullptr, output);
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintOperation::finish(const optional<vector<uint8_t>>& input,
                                               const optional<vector<uint8_t>>& signature,
                                               const optional<HardwareAuthToken>& authToken,
                                               const optional<TimeStampToken>& timestampToken,
                                               const optional<vector<uint8_t>>& confirmationToken,
                                               vector<uint8_t>* output) {
    ::keymaster::HardwareAuthToken legacyToken;
    vector<uint8_t> encodedTimestampToken;
    HardwareAuthToken aToken = authToken.value_or(HardwareAuthToken());
    TimeStampToken tToken = timestampToken.value_or(TimeStampToken());
    vector<uint8_t> inputData = input.value_or(vector<uint8_t>());
    vector<uint8_t> signatureData = signature.value_or(vector<uint8_t>());
    // If confirmation token is empty, then create empty vector. This is to
    // differentiate between the keymaster and keymint.
    std::optional<vector<uint8_t>> confToken = confirmationToken.value_or(vector<uint8_t>());
    legacyHardwareAuthToken(aToken, &legacyToken);
    encodeTimestampToken(tToken, &encodedTimestampToken);
    auto err = jcKmOprImpl_->finish(inputData, nullopt, signatureData, legacyToken,
                                    encodedTimestampToken, confToken, nullptr, output);
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintOperation::abort() {
    return km_utils::kmError2ScopedAStatus(jcKmOprImpl_->abort());
}

}  // namespace aidl::android::hardware::security::keymint
