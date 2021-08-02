#pragma once

#include "CborConverter.h"
#include "JavacardSecureElement.h"

#include <aidl/android/hardware/security/sharedsecret/BnSharedSecret.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>
#include <memory>
#include <vector>

namespace aidl::android::hardware::security::sharedsecret {
using namespace ::keymint::javacard;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;

class JavacardSharedSecret : public BnSharedSecret {
  public:
    explicit JavacardSharedSecret(shared_ptr<JavacardSecureElement> card) : card_(card) {}
    virtual ~JavacardSharedSecret() {}

    ScopedAStatus getSharedSecretParameters(SharedSecretParameters* params) override;

    ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                      std::vector<uint8_t>* secret) override;

  private:
    shared_ptr<JavacardSecureElement> card_;
    CborConverter cbor_;
};

}  // namespace aidl::android::hardware::security::sharedsecret
