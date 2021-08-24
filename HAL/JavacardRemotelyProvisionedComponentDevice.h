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

#pragma once

#include <aidl/android/hardware/security/keymint/BnRemotelyProvisionedComponent.h>
#include <aidl/android/hardware/security/keymint/RpcHardwareInfo.h>
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>
#include <cppbor.h>
#include <keymaster/UniquePtr.h>
#include <keymaster/android_keymaster.h>

#include "CborConverter.h"
#include "JavacardSecureElement.h"

namespace aidl::android::hardware::security::keymint {
using namespace ::keymint::javacard;
using ndk::ScopedAStatus;

class JavacardRemotelyProvisionedComponentDevice
    : public BnRemotelyProvisionedComponent {
 public:
  explicit JavacardRemotelyProvisionedComponentDevice(
      shared_ptr<JavacardSecureElement> card)
      : card_(card) {}

  virtual ~JavacardRemotelyProvisionedComponentDevice() = default;

  ScopedAStatus getHardwareInfo(RpcHardwareInfo* info) override;

  ScopedAStatus generateEcdsaP256KeyPair(
      bool testMode, MacedPublicKey* macedPublicKey,
      std::vector<uint8_t>* privateKeyHandle) override;

  ScopedAStatus generateCertificateRequest(
      bool testMode, const std::vector<MacedPublicKey>& keysToSign,
      const std::vector<uint8_t>& endpointEncCertChain,
      const std::vector<uint8_t>& challenge, DeviceInfo* deviceInfo,
      ProtectedData* protectedData,
      std::vector<uint8_t>* keysToSignMac) override;

 private:
  ScopedAStatus beginSendData(bool testMode,
                              const std::vector<MacedPublicKey>& keysToSign);

  ScopedAStatus updateMacedKey(const std::vector<MacedPublicKey>& keysToSign);

  ScopedAStatus updateChallenge(const std::vector<uint8_t>& challenge);

  ScopedAStatus updateEEK(const std::vector<uint8_t>& endpointEncCertChain);

  ScopedAStatus finishSendData(std::vector<uint8_t>* keysToSignMac,
                               DeviceInfo* deviceInfo,
                               std::vector<uint8_t>& coseEncryptProtectedHeader,
                               cppbor::Map& coseEncryptUnProtectedHeader,
                               std::vector<uint8_t>& partialCipheredData,
                               uint32_t& respFlag);

  ScopedAStatus getResponse(std::vector<uint8_t>& partialCipheredData,
                            cppbor::Array& recepientStructure,
                            uint32_t& respFlag);
  std::shared_ptr<JavacardSecureElement> card_;
  CborConverter cbor_;
};

}  // namespace aidl::android::hardware::security::keymint
