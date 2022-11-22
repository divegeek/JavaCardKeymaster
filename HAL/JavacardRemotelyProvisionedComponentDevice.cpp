/*
 * Copyright 2021, The Android Open Source Project
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

#define LOG_TAG "javacard.keymint.device.rkp.strongbox-impl"

#include "JavacardRemotelyProvisionedComponentDevice.h"

#include <aidl/android/hardware/security/keymint/MacedPublicKey.h>

#include <android-base/logging.h>
#include <keymaster/cppcose/cppcose.h>
#include <keymaster/remote_provisioning_utils.h>

#include "JavacardKeyMintUtils.h"

namespace aidl::android::hardware::security::keymint {

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::getHardwareInfo(RpcHardwareInfo* /*info*/) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateEcdsaP256KeyPair(bool /*testMode*/,
                                                MacedPublicKey* /*macedPublicKey*/,
                                                std::vector<uint8_t>* /*privateKeyHandle*/) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus
JavacardRemotelyProvisionedComponentDevice::generateCertificateRequest(bool /*testMode*/,
                                        const std::vector<MacedPublicKey>& /*keysToSign*/,
                                        const std::vector<uint8_t>& /*endpointEncCertChain*/,
                                        const std::vector<uint8_t>& /*challenge*/,
                                        DeviceInfo* /*deviceInfo*/, ProtectedData* /*protectedData*/,
                                        std::vector<uint8_t>* /*keysToSignMac*/) {
    return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

} // namespace aidl::android::hardware::security::keymint
