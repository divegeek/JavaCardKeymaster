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

#ifndef KEYMASTER_V4_0_JAVACARD_JAVACARDKEYMASTER4DEVICE_H_
#define KEYMASTER_V4_0_JAVACARD_JAVACARDKEYMASTER4DEVICE_H_

#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <android-base/properties.h>
#include "CborConverter.h"
#include "TransportFactory.h"
#include <cppbor.h>
#include <cppbor_parse.h>
#include <keymaster/keymaster_configuration.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/android_keymaster.h>
#include <JavacardOperationContext.h>

namespace keymaster {
namespace V4_0 {
namespace javacard {
#define INS_BEGIN_KM_CMD 0x00
#define INS_END_KM_PROVISION_CMD 0x20
#define INS_END_KM_CMD 0x7F

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
using ::android::hardware::keymaster::V4_0::IKeymasterDevice;
using ::android::hardware::keymaster::V4_0::Tag;

enum class OperationType {
    /* Public operations are processed inside softkeymaster */
    PUBLIC_OPERATION = 0,
    /* Private operations are processed inside strongbox */
    PRIVATE_OPERATION = 1,
    UNKNOWN = 2,
};

enum class Instruction {
    // Keymaster commands
    INS_GENERATE_KEY_CMD = INS_END_KM_PROVISION_CMD+1,
    INS_IMPORT_KEY_CMD = INS_END_KM_PROVISION_CMD+2,
    INS_IMPORT_WRAPPED_KEY_CMD = INS_END_KM_PROVISION_CMD+3,
    INS_EXPORT_KEY_CMD = INS_END_KM_PROVISION_CMD+4,
    INS_ATTEST_KEY_CMD = INS_END_KM_PROVISION_CMD+5,
    INS_UPGRADE_KEY_CMD = INS_END_KM_PROVISION_CMD+6,
    INS_DELETE_KEY_CMD = INS_END_KM_PROVISION_CMD+7,
    INS_DELETE_ALL_KEYS_CMD = INS_END_KM_PROVISION_CMD+8,
    INS_ADD_RNG_ENTROPY_CMD = INS_END_KM_PROVISION_CMD+9,
    INS_COMPUTE_SHARED_HMAC_CMD = INS_END_KM_PROVISION_CMD+10,
    INS_DESTROY_ATT_IDS_CMD = INS_END_KM_PROVISION_CMD+11,
    INS_VERIFY_AUTHORIZATION_CMD = INS_END_KM_PROVISION_CMD+12,
    INS_GET_HMAC_SHARING_PARAM_CMD = INS_END_KM_PROVISION_CMD+13,
    INS_GET_KEY_CHARACTERISTICS_CMD = INS_END_KM_PROVISION_CMD+14,
    INS_GET_HW_INFO_CMD = INS_END_KM_PROVISION_CMD+15,
    INS_BEGIN_OPERATION_CMD = INS_END_KM_PROVISION_CMD+16,
    INS_UPDATE_OPERATION_CMD = INS_END_KM_PROVISION_CMD+17,
    INS_FINISH_OPERATION_CMD = INS_END_KM_PROVISION_CMD+18,
    INS_ABORT_OPERATION_CMD = INS_END_KM_PROVISION_CMD+19,
    INS_DEVICE_LOCKED_CMD = INS_END_KM_PROVISION_CMD+20,
    INS_EARLY_BOOT_ENDED_CMD = INS_END_KM_PROVISION_CMD+21,
    INS_GET_CERT_CHAIN_CMD = INS_END_KM_PROVISION_CMD+22,
    INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD+7,
    INS_SET_VERSION_PATCHLEVEL_CMD = INS_BEGIN_KM_CMD+8,
};

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

  private:
    ErrorCode handleBeginPublicKeyOperation(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob,
                                            const hidl_vec<KeyParameter>& inParams,
                                            hidl_vec<KeyParameter>& outParams,
                                            uint64_t& operationHandle);

    ErrorCode handleBeginPrivateKeyOperation(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob,
                                             const hidl_vec<KeyParameter>& inParams,
                                             const HardwareAuthToken& authToken,
                                             hidl_vec<KeyParameter>& outParams,
                                             uint64_t& operationHandle);

    ErrorCode handleBeginOperation(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob,
                                   const hidl_vec<KeyParameter>& inParams,
                                   const HardwareAuthToken& authToken,
                                   hidl_vec<KeyParameter>& outParams, uint64_t& operationHandle,
                                   OperationType& operType);

    ErrorCode abortOperation(uint64_t operationHandle, OperationType operType);

    ErrorCode abortPublicKeyOperation(uint64_t operationHandle);

    ErrorCode abortPrivateKeyOperation(uint64_t operationHandle);

    ErrorCode sendData(Instruction ins, std::vector<uint8_t>& inData, std::vector<uint8_t>& response);
    ErrorCode setAndroidSystemProperties();

    std::unique_ptr<::keymaster::AndroidKeymaster> softKm_;
    std::unique_ptr<OperationContext> oprCtx_;
    bool isEachSystemPropertySet;
    CborConverter cborConverter_;
};

}  // namespace javacard
}  // namespace V4_0
}  // namespace keymaster

#endif  // KEYMASTER_V4_0_JAVACARD_JAVACARDKEYMASTER4DEVICE_H_
