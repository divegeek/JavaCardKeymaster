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
#pragma once

#include <JavacardKeymaster.h>
#include <aidl/android/hardware/security/sharedsecret/BnSharedSecret.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>
#include <memory>
#include <vector>

namespace aidl::android::hardware::security::sharedsecret {
using namespace ::javacard_keymaster;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;

class JavacardSharedSecret : public BnSharedSecret {
  public:
    explicit JavacardSharedSecret(shared_ptr<JavacardKeymaster> jcImpl) : jcImpl_(jcImpl) {}
    virtual ~JavacardSharedSecret() {}

    ScopedAStatus getSharedSecretParameters(SharedSecretParameters* params) override;

    ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                      std::vector<uint8_t>* secret) override;

  private:
    const shared_ptr<JavacardKeymaster> jcImpl_;
};

}  // namespace aidl::android::hardware::security::sharedsecret
