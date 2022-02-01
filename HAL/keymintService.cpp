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

#include "JavacardKeyMintDevice.h"
#include "JavacardRemotelyProvisionedComponentDevice.h"
#include "JavacardSecureElement.h"
#include "JavacardSharedSecret.h"
#include "KMUtils.h"
#include <JavacardKeymaster.h>
#include <SocketTransport.h>
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <keymaster/km_version.h>

using namespace javacard_keymaster;
using aidl::android::hardware::security::keymint::JavacardKeyMintDevice;
using aidl::android::hardware::security::keymint::JavacardRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::keymint::JavacardSharedSecret;
using aidl::android::hardware::security::keymint::SecurityLevel;
using ::javacard_keymaster::JavacardKeymaster;
using ::javacard_keymaster::JavacardSecureElement;
using ::javacard_keymaster::SocketTransport;

template <typename T, class... Args> std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/strongbox";
    LOG(INFO) << "adding javacard strongbox service instance: " << instanceName;
    binder_status_t status =
        AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);
    return ser;
}

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Javacard Secure Element
    std::shared_ptr<JavacardSecureElement> card = std::make_shared<JavacardSecureElement>(
        KmVersion::KEYMINT_1, std::make_shared<SocketTransport>(), getOsVersion(),
        getOsPatchlevel(), getVendorPatchlevel());
    std::shared_ptr<JavacardKeymaster> jcImpl = std::make_shared<JavacardKeymaster>(card);
    // Add Keymint Service
    addService<JavacardKeyMintDevice>(jcImpl);
    // Add Shared Secret Service
    addService<JavacardSharedSecret>(jcImpl);
    // Add Remotely Provisioned Component Service
    addService<JavacardRemotelyProvisionedComponentDevice>(card);

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
