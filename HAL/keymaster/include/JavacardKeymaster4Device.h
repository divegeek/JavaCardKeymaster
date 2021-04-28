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

#ifndef KEYMASTER_V4_1_JAVACARD_JAVACARDKEYMASTER4DEVICE_H_
#define KEYMASTER_V4_1_JAVACARD_JAVACARDKEYMASTER4DEVICE_H_

#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <android-base/properties.h>
#include "CborConverter.h"
#include "TransportFactory.h"
#include <keymaster/keymaster_configuration.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/android_keymaster.h>
#include <JavacardOperationContext.h>

namespace keymaster {
namespace V4_1 {
namespace javacard {

using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;
using ::android::hardware::Void;

using ::android::hardware::keymaster::V4_0::ErrorCode;
using ::android::hardware::keymaster::V4_0::HardwareAuthenticatorType;
using ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using ::android::hardware::keymaster::V4_0::HmacSharingParameters;
using ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using ::android::hardware::keymaster::V4_0::KeyFormat;
using ::android::hardware::keymaster::V4_0::KeyParameter;
using ::android::hardware::keymaster::V4_0::KeyPurpose;
using ::android::hardware::keymaster::V4_0::OperationHandle;
using ::android::hardware::keymaster::V4_0::SecurityLevel;
using ::android::hardware::keymaster::V4_0::VerificationToken;
using ::android::hardware::keymaster::V4_1::IKeymasterDevice;
using ::android::hardware::keymaster::V4_0::Tag;

using V41ErrorCode = ::android::hardware::keymaster::V4_1::ErrorCode;

class JavacardKeymaster4Device : public IKeymasterDevice {
  public:
  
    JavacardKeymaster4Device();
    virtual ~JavacardKeymaster4Device();

    // Methods from ::android::hardware::keymaster::V4_0::IKeymasterDevice follow.
    Return<void> getHardwareInfo(getHardwareInfo_cb _hidl_cb) override;
    Return<void> getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) override;
    Return<void> computeSharedHmac(const hidl_vec<HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) override;
    Return<void> verifyAuthorization(uint64_t operationHandle, const hidl_vec<KeyParameter>& parametersToVerify, const HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) override;
    Return<ErrorCode> addRngEntropy(const hidl_vec<uint8_t>& data) override;
    Return<void> generateKey(const hidl_vec<KeyParameter>& keyParams, generateKey_cb _hidl_cb) override;
    Return<void> importKey(const hidl_vec<KeyParameter>& keyParams, KeyFormat keyFormat, const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) override;
    Return<void> importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob, const hidl_vec<uint8_t>& maskingKey, const hidl_vec<KeyParameter>& unwrappingParams, uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) override;
    Return<void> getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, getKeyCharacteristics_cb _hidl_cb) override;
    Return<void> exportKey(KeyFormat keyFormat, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) override;
    Return<void> attestKey(const hidl_vec<uint8_t>& keyToAttest, const hidl_vec<KeyParameter>& attestParams, attestKey_cb _hidl_cb) override;
    Return<void> upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade, const hidl_vec<KeyParameter>& upgradeParams, upgradeKey_cb _hidl_cb) override;
    Return<ErrorCode> deleteKey(const hidl_vec<uint8_t>& keyBlob) override;
    Return<ErrorCode> deleteAllKeys() override;
    Return<ErrorCode> destroyAttestationIds() override;
    Return<void> begin(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams, const HardwareAuthToken& authToken, begin_cb _hidl_cb) override;
    Return<void> update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, update_cb _hidl_cb) override;
    Return<void> finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams, const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature, const HardwareAuthToken& authToken, const VerificationToken& verificationToken, finish_cb _hidl_cb) override;
    Return<ErrorCode> abort(uint64_t operationHandle) override;

    // Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
    Return<V41ErrorCode> deviceLocked(bool passwordOnly, const VerificationToken& verificationToken) override;
    Return<V41ErrorCode> earlyBootEnded() override;

protected:
    CborConverter cborConverter_;
	
private:
    std::unique_ptr<::keymaster::AndroidKeymaster> softKm_;
    std::unique_ptr<OperationContext> oprCtx_;
    bool isEachSystemPropertySet;
};

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster

#endif  // KEYMASTER_V4_1_JAVACARD_JAVACARDKEYMASTER4DEVICE_H_
