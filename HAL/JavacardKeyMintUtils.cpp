/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "JavacardKeyMintUtils.h"
#include <cppbor.h>

namespace aidl::android::hardware::security::keymint {

keymaster_error_t legacyHardwareAuthToken(const HardwareAuthToken& aidlToken,
                                          LegacyHardwareAuthToken* legacyToken) {
    legacyToken->challenge = aidlToken.challenge;
    legacyToken->user_id = aidlToken.userId;
    legacyToken->authenticator_id = aidlToken.authenticatorId;
    legacyToken->authenticator_type =
        static_cast<hw_authenticator_type_t>(aidlToken.authenticatorType);
    legacyToken->timestamp = aidlToken.timestamp.milliSeconds;
    Vec2KmBlob(aidlToken.mac, &legacyToken->mac);
    return KM_ERROR_OK;
}

keymaster_error_t encodeTimestampToken(const TimeStampToken& timestampToken,
                                       vector<uint8_t>* encodedToken) {
    cppbor::Array array;
    ::keymaster::TimestampToken token;
    array.add(static_cast<uint64_t>(timestampToken.challenge));
    array.add(static_cast<uint64_t>(timestampToken.timestamp.milliSeconds));
    array.add(timestampToken.mac);
    *encodedToken = array.encode();
    return KM_ERROR_OK;
}

}  // namespace aidl::android::hardware::security::keymint
