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

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include "JavacardKeyMintDevice.h"
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>

#include "keymint_utils.h"
#include "JavacardSharedSecret.h"
//#include "JavacardRemotelyProvisionedComponentDevice.h"
#include <SocketTransport.h>

using aidl::android::hardware::security::keymint::JavacardKeyMintDevice;
using aidl::android::hardware::security::keymint::JavacardSharedSecret;
using aidl::android::hardware::security::keymint::SecurityLevel;
using namespace keymint::javacard;

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
    // Add Keymint Service

    std::shared_ptr<JavacardKeyMintDevice> keyMint =
        addService<JavacardKeyMintDevice>(std::make_shared<SocketTransport>(), getOsVersion(),
                                          getOsPatchlevel(), getVendorPatchlevel());
    // Add Shared Secret Service
        addService<JavacardSharedSecret>(keyMint);
    // Add Remotely Provisioned Component Service
      //  addService<JavacardRemotelyProvisionedComponentDevice>(keyMint);
        
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
