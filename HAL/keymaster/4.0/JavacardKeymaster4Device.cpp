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

#define LOG_TAG "android.hardware.keymaster@4.0-impl.trusty"

#include <keymaster/authorization_set.h>
#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <JavacardKeymaster4Device.h>

/* TODO Remove below UNUSED */
#define UNUSED(a) a=a

namespace keymaster {
namespace V4_0 {

JavacardKeymaster4Device::JavacardKeymaster4Device() {
    // TODO
}

JavacardKeymaster4Device::~JavacardKeymaster4Device() {
}

// Methods from ::android::hardware::keymaster::V4_0::IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    // TODO implement
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    // TODO implement
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    // TODO implement
    size_t size = params.size();
    UNUSED(size);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& parametersToVerify, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) {
    // TODO implement
    UNUSED(operationHandle);
    size_t size = parametersToVerify.size();
    UNUSED(size);
    uint64_t challenge = authToken.challenge;
    UNUSED(challenge);
    UNUSED(_hidl_cb);
    return Void();
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    // TODO implement
    size_t size = data.size();
    UNUSED(size);
    return ::android::hardware::keymaster::V4_0::ErrorCode {};
}

Return<void> JavacardKeymaster4Device::generateKey(const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams, generateKey_cb _hidl_cb) {
    // TODO implement
    UNUSED(_hidl_cb);
    size_t size = keyParams.size();
    UNUSED(size);
    return Void();
}

Return<void> JavacardKeymaster4Device::importKey(const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams, ::android::hardware::keymaster::V4_0::KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
    // TODO implement
    size_t size = keyParams.size();
    size = keyData.size();
    UNUSED(size);
    UNUSED(keyFormat);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob, const hidl_vec<uint8_t>& maskingKey, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& unwrappingParams, uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {
    // TODO implement
    size_t size = wrappedKeyData.size();
    size = wrappingKeyBlob.size();
    size = maskingKey.size();
    size = unwrappingParams.size();
    UNUSED(size);
    UNUSED(passwordSid);
    UNUSED(biometricSid);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) {
    // TODO implement
    size_t size = keyBlob.size();
    size = clientId.size();
    size = appData.size();
    UNUSED(size);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::exportKey(::android::hardware::keymaster::V4_0::KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    // TODO implement
    size_t size = clientId.size();
    size = keyBlob.size();
    size = appData.size();
    UNUSED(size);
    UNUSED(keyFormat);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& attestParams, attestKey_cb _hidl_cb) {
    // TODO implement
    size_t size = attestParams.size();
    size = keyToAttest.size();
    UNUSED(size);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) {
    // TODO implement
    size_t size = keyBlobToUpgrade.size();
    size = upgradeParams.size();
    UNUSED(size);
    UNUSED(_hidl_cb);
    return Void();
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    // TODO implement
    size_t size = keyBlob.size();
    UNUSED(size);
    return ::android::hardware::keymaster::V4_0::ErrorCode {};
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    // TODO implement
    return ::android::hardware::keymaster::V4_0::ErrorCode {};
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    // TODO implement
    return ::android::hardware::keymaster::V4_0::ErrorCode {};
}

Return<void> JavacardKeymaster4Device::begin(::android::hardware::keymaster::V4_0::KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    // TODO implement
    UNUSED(purpose);
    size_t size = keyBlob.size();
    size = inParams.size();
    UNUSED(size);
    uint64_t challenge = authToken.challenge;
    UNUSED(challenge);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::update(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken, update_cb _hidl_cb) {
    // TODO implement
    UNUSED(operationHandle);
    size_t size = inParams.size();
    size = input.size();
    UNUSED(size);
    uint64_t challange = verificationToken.challenge;
    challange = authToken.challenge;
    UNUSED(challange);
    UNUSED(_hidl_cb);
    return Void();
}

Return<void> JavacardKeymaster4Device::finish(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken, finish_cb _hidl_cb) {
    // TODO implement
    UNUSED(operationHandle);
    size_t size = inParams.size();
    size = input.size();
    size = signature.size();
    uint64_t challange = authToken.challenge;
    challange = verificationToken.challenge;
    UNUSED(challange);
    UNUSED(_hidl_cb);
    return Void();
}

Return<::android::hardware::keymaster::V4_0::ErrorCode> JavacardKeymaster4Device::abort(uint64_t operationHandle) {
    // TODO implement
    UNUSED(operationHandle);
    return ::android::hardware::keymaster::V4_0::ErrorCode {};
}


// Methods from ::android::hidl::base::V1_0::IBase follow.

//IKeymasterDevice* HIDL_FETCH_IKeymasterDevice(const char* /* name */) {
    //return new JavacardKeymaster4Device();
//}
//
}  // namespace android::hardware::keymaster::implementation
}
