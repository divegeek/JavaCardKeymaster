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
