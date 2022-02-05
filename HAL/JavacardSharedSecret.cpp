/*
 **
 ** Copyright 2021, The Android Open Source Project
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
#define LOG_TAG "javacard.strongbox.keymint.operation-impl"
#include "JavacardSharedSecret.h"
#include <KeyMintUtils.h>
#include <android-base/logging.h>

namespace aidl::android::hardware::security::sharedsecret {
using aidl::android::hardware::security::keymint::km_utils::kmError2ScopedAStatus;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;

ScopedAStatus JavacardSharedSecret::getSharedSecretParameters(SharedSecretParameters* params) {
    auto err = jcImpl_->getHmacSharingParameters(&params->seed, &params->nonce);
    return kmError2ScopedAStatus(err);
}

ScopedAStatus
JavacardSharedSecret::computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                          std::vector<uint8_t>* secret) {

    vector<::javacard_keymaster::HmacSharingParameters> reqParams(params.size());
    for (size_t i = 0; i < params.size(); i++) {
        reqParams[i].seed = params[i].seed;
        reqParams[i].nonce = params[i].nonce;
    }
    auto err = jcImpl_->computeSharedHmac(reqParams, secret);
    return kmError2ScopedAStatus(err);
}

}  // namespace aidl::android::hardware::security::sharedsecret
