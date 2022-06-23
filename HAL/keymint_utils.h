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

#include <string>
#include <vector>

//#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>

// namespace aidl::android::hardware::security::keymint {
namespace keymint::javacard {

using std::vector;

inline static std::vector<uint8_t> blob2vector(const uint8_t* data, const size_t length) {
    std::vector<uint8_t> result(data, data + length);
    return result;
}

inline static std::vector<uint8_t> blob2vector(const std::string& value) {
    vector<uint8_t> result(reinterpret_cast<const uint8_t*>(value.data()),
                           reinterpret_cast<const uint8_t*>(value.data()) + value.size());
    return result;
}

// HardwareAuthToken vector2AuthToken(const vector<uint8_t>& buffer);
// vector<uint8_t> authToken2vector(const HardwareAuthToken& token);

uint32_t getOsVersion();
uint32_t getOsPatchlevel();
uint32_t getVendorPatchlevel();

}  // namespace keymint::javacard
