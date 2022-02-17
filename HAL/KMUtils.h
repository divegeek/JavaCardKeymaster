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

#include <hardware/keymaster_defs.h>
#include <keymaster/authorization_set.h>
#include <keymaster/serializable.h>
#include <string>
#include <vector>

namespace javacard_keymaster {
using namespace ::keymaster;
using std::vector;

// Extended error codes
enum ExtendedErrors {
    SW_CONDITIONS_NOT_SATISFIED = -10001,
    UNSUPPORTED_CLA = -10002,
    INVALID_P1P2 = -10003,
    UNSUPPORTED_INSTRUCTION = -10004,
    CMD_NOT_ALLOWED = -10005,
    SW_WRONG_LENGTH = -10006,
    INVALID_DATA = -10007,
    CRYPTO_ILLEGAL_USE = -10008,
    CRYPTO_ILLEGAL_VALUE = -10009,
    CRYPTO_INVALID_INIT = -10010,
    CRYPTO_NO_SUCH_ALGORITHM = -10011,
    CRYPTO_UNINITIALIZED_KEY = -10012,
    GENERIC_UNKNOWN_ERROR = -10013,
    PUBLIC_KEY_OPERATION = -10014,
};

inline static std::vector<uint8_t> blob2vector(const uint8_t* data, const size_t length) {
    std::vector<uint8_t> result(data, data + length);
    return result;
}

inline static std::vector<uint8_t> blob2vector(const std::string& value) {
    vector<uint8_t> result(reinterpret_cast<const uint8_t*>(value.data()),
                           reinterpret_cast<const uint8_t*>(value.data()) + value.size());
    return result;
}

inline void blob2Vec(const uint8_t* from, size_t size, std::vector<uint8_t>& to) {
    for (size_t i = 0; i < size; ++i) {
        to.push_back(from[i]);
    }
}

// HardwareAuthToken vector2AuthToken(const vector<uint8_t>& buffer);
// vector<uint8_t> authToken2vector(const HardwareAuthToken& token);
keymaster_error_t translateExtendedErrorsToHalErrors(keymaster_error_t errorCode);
uint32_t getOsVersion();
uint32_t getOsPatchlevel();
uint32_t getVendorPatchlevel();
void addCreationTime(AuthorizationSet& paramSet);

keymaster_error_t getCertificateChain(std::vector<uint8_t>& chainBuffer,
                                      std::vector<std::vector<uint8_t>>& certChain);
}  // namespace javacard_keymaster
