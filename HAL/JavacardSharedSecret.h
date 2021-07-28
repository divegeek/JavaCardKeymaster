#pragma once

#include "JavacardKeyMintDevice.h"
#include <aidl/android/hardware/security/sharedsecret/BnSharedSecret.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>
#include <memory>
#include <vector>

namespace aidl::android::hardware::security::sharedsecret {
using namespace aidl::android::hardware::security::keymint;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;

class JavacardSharedSecret : public BnSharedSecret {
  public:
    explicit JavacardSharedSecret(shared_ptr<JavacardKeyMintDevice> keymint) : keymint_(keymint) {}
    virtual ~JavacardSharedSecret() {}

    ScopedAStatus getSharedSecretParameters(SharedSecretParameters* params) override {
        return keymint_->getSharedSecretParameters(params);
    }

    ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                      std::vector<uint8_t>* secret) override {
        return keymint_->computeSharedSecret(params, secret);
    }

  private:
    shared_ptr<JavacardKeyMintDevice> keymint_;
};

}  // namespace aidl::android::hardware::security::sharedsecret
