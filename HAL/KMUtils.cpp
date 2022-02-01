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

#include <KMUtils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <keymaster/android_keymaster_utils.h>
#include <regex.h>

#define TAG_SEQUENCE 0x30
#define LENGTH_MASK 0x80
#define LENGTH_VALUE_MASK 0x7F

namespace javacard_keymaster {
namespace {

constexpr char kPlatformVersionProp[] = "ro.build.version.release";
constexpr char kPlatformVersionRegex[] = "^([0-9]{1,2})(\\.([0-9]{1,2}))?(\\.([0-9]{1,2}))?";
constexpr size_t kMajorVersionMatch = 1;
constexpr size_t kMinorVersionMatch = 3;
constexpr size_t kSubminorVersionMatch = 5;
constexpr size_t kPlatformVersionMatchCount = kSubminorVersionMatch + 1;

constexpr char kPlatformPatchlevelProp[] = "ro.build.version.security_patch";
constexpr char kVendorPatchlevelProp[] = "ro.vendor.build.security_patch";
constexpr char kPatchlevelRegex[] = "^([0-9]{4})-([0-9]{2})-([0-9]{2})$";
constexpr size_t kYearMatch = 1;
constexpr size_t kMonthMatch = 2;
constexpr size_t kDayMatch = 3;
constexpr size_t kPatchlevelMatchCount = kDayMatch + 1;

uint32_t match_to_uint32(const char* expression, const regmatch_t& match) {
    if (match.rm_so == -1) return 0;

    size_t len = match.rm_eo - match.rm_so;
    std::string s(expression + match.rm_so, len);
    return std::stoul(s);
}

std::string wait_and_get_property(const char* prop) {
    std::string prop_value;
    while (!::android::base::WaitForPropertyCreation(prop))
        ;
    prop_value = ::android::base::GetProperty(prop, "" /* default */);
    return prop_value;
}

uint32_t getOsVersion(const char* version_str) {
    regex_t regex;
    if (regcomp(&regex, kPlatformVersionRegex, REG_EXTENDED)) {
        return 0;
    }

    regmatch_t matches[kPlatformVersionMatchCount];
    int not_match =
        regexec(&regex, version_str, kPlatformVersionMatchCount, matches, 0 /* flags */);
    regfree(&regex);
    if (not_match) {
        return 0;
    }

    uint32_t major = match_to_uint32(version_str, matches[kMajorVersionMatch]);
    uint32_t minor = match_to_uint32(version_str, matches[kMinorVersionMatch]);
    uint32_t subminor = match_to_uint32(version_str, matches[kSubminorVersionMatch]);

    return (major * 100 + minor) * 100 + subminor;
}

enum class PatchlevelOutput { kYearMonthDay, kYearMonth };

uint32_t getPatchlevel(const char* patchlevel_str, PatchlevelOutput detail) {
    regex_t regex;
    if (regcomp(&regex, kPatchlevelRegex, REG_EXTENDED) != 0) {
        return 0;
    }

    regmatch_t matches[kPatchlevelMatchCount];
    int not_match = regexec(&regex, patchlevel_str, kPatchlevelMatchCount, matches, 0 /* flags */);
    regfree(&regex);
    if (not_match) {
        return 0;
    }

    uint32_t year = match_to_uint32(patchlevel_str, matches[kYearMatch]);
    uint32_t month = match_to_uint32(patchlevel_str, matches[kMonthMatch]);

    if (month < 1 || month > 12) {
        return 0;
    }

    switch (detail) {
    case PatchlevelOutput::kYearMonthDay: {
        uint32_t day = match_to_uint32(patchlevel_str, matches[kDayMatch]);
        if (day < 1 || day > 31) {
            return 0;
        }
        return year * 10000 + month * 100 + day;
    }
    case PatchlevelOutput::kYearMonth:
        return year * 100 + month;
    }
}

}  // anonymous namespace

// TODO Can we move it to JavacardSecureElement class
keymaster_error_t translateExtendedErrorsToHalErrors(keymaster_error_t errorCode) {
    keymaster_error_t err = errorCode;
    switch (static_cast<int32_t>(errorCode)) {
    case SW_CONDITIONS_NOT_SATISFIED:
    case UNSUPPORTED_CLA:
    case INVALID_P1P2:
    case INVALID_DATA:
    case CRYPTO_ILLEGAL_USE:
    case CRYPTO_ILLEGAL_VALUE:
    case CRYPTO_INVALID_INIT:
    case CRYPTO_UNINITIALIZED_KEY:
    case GENERIC_UNKNOWN_ERROR:
        LOG(ERROR) << "translateExtendedErrorsToHalErrors SE error: " << (int32_t)errorCode;
        err = KM_ERROR_UNKNOWN_ERROR;
        break;
    case CRYPTO_NO_SUCH_ALGORITHM:
        LOG(ERROR) << "translateExtendedErrorsToHalErrors SE error: " << (int32_t)errorCode;
        err = KM_ERROR_UNSUPPORTED_ALGORITHM;
        break;
    case UNSUPPORTED_INSTRUCTION:
    case CMD_NOT_ALLOWED:
    case SW_WRONG_LENGTH:
        LOG(ERROR) << "translateExtendedErrorsToHalErrors SE error: " << (int32_t)errorCode;
        err = KM_ERROR_UNIMPLEMENTED;
        break;
    case PUBLIC_KEY_OPERATION:
        // This error is handled inside keymaster
        LOG(ERROR) << "translateExtendedErrorsToHalErrors SE error: " << (int32_t)errorCode;
        break;
    default:
        break;
    }
    return err;
}

uint32_t getOsVersion() {
    std::string version = wait_and_get_property(kPlatformVersionProp);
    return getOsVersion(version.c_str());
}

uint32_t getOsPatchlevel() {
    std::string patchlevel = wait_and_get_property(kPlatformPatchlevelProp);
    return getPatchlevel(patchlevel.c_str(), PatchlevelOutput::kYearMonth);
}

uint32_t getVendorPatchlevel() {
    std::string patchlevel = wait_and_get_property(kVendorPatchlevelProp);
    return getPatchlevel(patchlevel.c_str(), PatchlevelOutput::kYearMonthDay);
}

keymaster_error_t getCertificateChain(std::vector<uint8_t>& chainBuffer,
                                      std::vector<std::vector<uint8_t>>& certChain) {
    uint8_t* data = chainBuffer.data();
    int index = 0;
    uint32_t length = 0;
    while (index < chainBuffer.size()) {
        std::vector<uint8_t> temp;
        if (data[index] == TAG_SEQUENCE) {
            // read next byte
            if (0 == (data[index + 1] & LENGTH_MASK)) {
                length = (uint32_t)data[index];
                // Add SEQ and Length fields
                length += 2;
            } else {
                int additionalBytes = data[index + 1] & LENGTH_VALUE_MASK;
                if (additionalBytes == 0x01) {
                    length = data[index + 2];
                    // Add SEQ and Length fields
                    length += 3;
                } else if (additionalBytes == 0x02) {
                    length = (data[index + 2] << 8 | data[index + 3]);
                    // Add SEQ and Length fields
                    length += 4;
                } else if (additionalBytes == 0x04) {
                    length = data[index + 2] << 24;
                    length |= data[index + 3] << 16;
                    length |= data[index + 4] << 8;
                    length |= data[index + 5];
                    // Add SEQ and Length fields
                    length += 6;
                } else {
                    // Length is larger than uint32_t max limit.
                    return KM_ERROR_UNKNOWN_ERROR;
                }
            }
            temp.insert(temp.end(), (data + index), (data + index + length));
            index += length;

            certChain.push_back(std::move(temp));
        } else {
            // SEQUENCE TAG MISSING.
            return KM_ERROR_UNKNOWN_ERROR;
        }
    }
    return KM_ERROR_OK;
}

void addCreationTime(AuthorizationSet& paramSet) {
    if (!paramSet.Contains(KM_TAG_CREATION_DATETIME) &&
        !paramSet.Contains(KM_TAG_ACTIVE_DATETIME)) {
        keymaster_key_param_t dateTime;
        dateTime.tag = KM_TAG_CREATION_DATETIME;
        dateTime.date_time = java_time(time(nullptr));
        paramSet.push_back(dateTime);
    }
}

}  // namespace javacard_keymaster
