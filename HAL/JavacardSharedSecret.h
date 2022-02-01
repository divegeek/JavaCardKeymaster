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
