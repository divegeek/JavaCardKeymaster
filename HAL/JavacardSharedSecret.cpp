#define LOG_TAG "javacard.strongbox.keymint.operation-impl"
#include <android-base/logging.h>

#include "JavacardSharedSecret.h"
#include <JavacardKeyMintUtils.h>

namespace aidl::android::hardware::security::sharedsecret {
using namespace ::keymint::javacard;
using ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::vector;

ScopedAStatus JavacardSharedSecret::getSharedSecretParameters(SharedSecretParameters* params) {
    auto error = card_->initializeJavacard();
    if(error != KM_ERROR_OK) {
        LOG(ERROR) << "Error in initializing javacard.";
        return km_utils::kmError2ScopedAStatus(error);    
    }
    auto [item, err] = card_->sendRequest(Instruction::INS_GET_SHARED_SECRET_PARAM_CMD);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in getSharedSecretParameters.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!cbor_.getSharedSecretParameters(item, 1, *params)) {
        LOG(ERROR) << "Error in sending in getSharedSecretParameters.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus
JavacardSharedSecret::computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                          std::vector<uint8_t>* secret) {

    auto error = card_->initializeJavacard();
    if(error != KM_ERROR_OK) {
        LOG(ERROR) << "Error in initializing javacard.";
        return km_utils::kmError2ScopedAStatus(error);    
    }
    cppbor::Array request;
    cbor_.addSharedSecretParameters(request, params);
    auto [item, err] = card_->sendRequest(Instruction::INS_COMPUTE_SHARED_SECRET_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending in computeSharedSecret.";
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!cbor_.getBinaryArray(item, 1, *secret)) {
        LOG(ERROR) << "Error in decoding the response in computeSharedSecret.";
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNKNOWN_ERROR);
    }
    return ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::security::sharedsecret
