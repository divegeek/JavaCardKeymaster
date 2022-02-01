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

#pragma once
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <vector>

namespace aidl::android::hardware::security::keymint {
using namespace ::keymaster;
using secureclock::TimeStampToken;
using std::vector;
using LegacyHardwareAuthToken = ::keymaster::HardwareAuthToken;

inline void Vec2KmBlob(const vector<uint8_t>& input, KeymasterBlob* blob) {
    blob->Reset(input.size());
    memcpy(blob->writable_data(), input.data(), input.size());
}

keymaster_error_t legacyHardwareAuthToken(const HardwareAuthToken& aidlToken,
                                          LegacyHardwareAuthToken* legacyToken);

keymaster_error_t encodeTimestampToken(const TimeStampToken& timestampToken,
                                       vector<uint8_t>* encodedToken);

}  // namespace aidl::android::hardware::security::keymint
