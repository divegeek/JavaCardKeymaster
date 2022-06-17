/*
 * Copyright 2020, The Android Open Source Project
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

#define LOG_TAG "javacard.strongbox-service"

#include <aidl/android/hardware/security/keymint/SecurityLevel.h>

#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android-base/logging.h>
#include <android-base/properties.h>

#include "JavacardKeyMintDevice.h"
#include "JavacardSecureElement.h"
#include "JavacardSharedSecret.h"
#include "JavacardRemotelyProvisionedComponentDevice.h"
#include "keymint_utils.h"
#include "OmapiTransport.h"
#include "SocketTransport.h"

using aidl::android::hardware::security::keymint::JavacardKeyMintDevice;
using aidl::android::hardware::security::keymint::JavacardSharedSecret;
using aidl::android::hardware::security::keymint::SecurityLevel;
using namespace keymint::javacard;

#define PROP_BUILD_QEMU              "ro.kernel.qemu"
#define PROP_BUILD_FINGERPRINT       "ro.build.fingerprint"
// Cuttlefish build fingerprint substring.
#define CUTTLEFISH_FINGERPRINT_SS    "aosp_cf_"

template <typename T, class... Args> std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/strongbox";
    LOG(INFO) << "adding javacard strongbox service instance: " << instanceName;
    binder_status_t status =
        AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);
    return ser;
}

std::shared_ptr<ITransport> getTransportInstance() {
    bool isEmulator = false;
    // Check if the current build is for emulator or device.
    isEmulator = android::base::GetBoolProperty(PROP_BUILD_QEMU, false);
    if (!isEmulator) {
        std::string fingerprint = android::base::GetProperty(PROP_BUILD_FINGERPRINT, "");
        if (!fingerprint.empty()) {
            if (fingerprint.find(CUTTLEFISH_FINGERPRINT_SS, 0) != std::string::npos) {
                isEmulator = true;
            }
        }
    }

    if (!isEmulator) {
        return std::make_shared<OmapiTransport>();
    } else {
        return std::make_shared<SocketTransport>();
    }
}

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Javacard Secure Element
    std::shared_ptr<JavacardSecureElement> card =
        std::make_shared<JavacardSecureElement>(getTransportInstance(), getOsVersion(),
                                                getOsPatchlevel(), getVendorPatchlevel());
    // Add Keymint Service
    addService<JavacardKeyMintDevice>(card);
    // Add Shared Secret Service
    addService<JavacardSharedSecret>(card);
    // Add Remotely Provisioned Component Service
    addService<JavacardRemotelyProvisionedComponentDevice>(card);

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
