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

#ifndef ANDROID_HARDWARE_KEYMASTER_V4_1_JAVACARDKEYMASTER4DEVICE_H_
#define ANDROID_HARDWARE_KEYMASTER_V4_1_JAVACARDKEYMASTER4DEVICE_H_

#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <android-base/properties.h>
#include "CborConverter.h"
#include "TransportFactory.h"

namespace android {
namespace hardware {
namespace keymaster {
namespace V4_1 {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

class JavacardKeymaster4Device : public IKeymasterDevice {
  public:
    JavacardKeymaster4Device() {
        if(android::base::GetBoolProperty("ro.kernel.qemu", false))
           pTransportFactory = std::make_unique<se_transport::TransportFactory>(true);
        else
           pTransportFactory = std::make_unique<se_transport::TransportFactory>(false);
    }

    virtual ~JavacardKeymaster4Device();

    // Methods from ::android::hardware::keymaster::V4_0::IKeymasterDevice follow.
    Return<void> getHardwareInfo(getHardwareInfo_cb _hidl_cb) override;
    Return<void> getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) override;
    Return<void> computeSharedHmac(const hidl_vec<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) override;
    Return<void> verifyAuthorization(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& parametersToVerify, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) override;
    Return<::android::hardware::keymaster::V4_0::ErrorCode> addRngEntropy(const hidl_vec<uint8_t>& data) override;
    Return<void> generateKey(const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams, generateKey_cb _hidl_cb) override;
    Return<void> importKey(const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& keyParams, ::android::hardware::keymaster::V4_0::KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) override;
    Return<void> importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob, const hidl_vec<uint8_t>& maskingKey, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& unwrappingParams, uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) override;
    Return<void> getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) override;
    Return<void> exportKey(::android::hardware::keymaster::V4_0::KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) override;
    Return<void> attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& attestParams, attestKey_cb _hidl_cb) override;
    Return<void> upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) override;
    Return<::android::hardware::keymaster::V4_0::ErrorCode> deleteKey(const hidl_vec<uint8_t>& keyBlob) override;
    Return<::android::hardware::keymaster::V4_0::ErrorCode> deleteAllKeys() override;
    Return<::android::hardware::keymaster::V4_0::ErrorCode> destroyAttestationIds() override;
    Return<void> begin(::android::hardware::keymaster::V4_0::KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, begin_cb _hidl_cb) override;
    Return<void> update(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken, update_cb _hidl_cb) override;
    Return<void> finish(uint64_t operationHandle, const hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken, finish_cb _hidl_cb) override;
    Return<::android::hardware::keymaster::V4_0::ErrorCode> abort(uint64_t operationHandle) override;

    // Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
    Return<::android::hardware::keymaster::V4_1::ErrorCode> deviceLocked(bool passwordOnly, const ::android::hardware::keymaster::V4_0::VerificationToken& verificationToken) override;
    Return<::android::hardware::keymaster::V4_1::ErrorCode> earlyBootEnded() override;

protected:
    CborConverter cborConverter_;
    std::unique_ptr<se_transport::TransportFactory> pTransportFactory;
};

}  // namespace V4_1
}  // namespace keymaster
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_KEYMASTER_V4_1_JAVACARDKEYMASTER4DEVICE_H_
