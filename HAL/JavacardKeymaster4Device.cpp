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
#include <CborConverter.h>

#include <JavacardKeymaster4Device.h>
#include <KMUtils.h>
#include <android-base/logging.h>
#include <keymaster/km_openssl/attestation_record.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <keymasterV4_0/keymaster_utils.h>
#include <time.h>

#define JAVACARD_KEYMASTER_NAME "JavacardKeymaster4.1Device v1.0"
#define JAVACARD_KEYMASTER_AUTHOR "Android Open Source Project"
#define PROP_BUILD_QEMU "ro.kernel.qemu"
#define PROP_BUILD_FINGERPRINT "ro.build.fingerprint"

namespace keymaster {
namespace V4_1 {
namespace javacard {
using namespace ::javacard_keymaster;
using android::hardware::keymaster::V4_0::support::authToken2HidlVec;
using std::string;
using std::vector;

constexpr size_t kOperationTableSize = 4;
constexpr int kKeyblobKeyCharsOffset = 3;

struct KM_AUTH_LIST_Delete {
    void operator()(KM_AUTH_LIST* p) { KM_AUTH_LIST_free(p); }
};

namespace {

inline keymaster_purpose_t legacy_enum_conversion(const KeyPurpose value) {
    return static_cast<keymaster_purpose_t>(value);
}

inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return static_cast<ErrorCode>(value);
}

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return keymaster_tag_t(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return Tag(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

inline keymaster_security_level_t legacy_enum_conversion(const SecurityLevel value) {
    return static_cast<keymaster_security_level_t>(value);
}

inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return static_cast<keymaster_key_format_t>(value);
}

inline void hidlVec2KmBlob(const hidl_vec<uint8_t>& input, KeymasterBlob* blob) {
    blob->Reset(input.size());
    memcpy(blob->writable_data(), input.data(), input.size());
}

void legacyHardwareAuthToken(const HardwareAuthToken& hidlToken,
                             ::keymaster::HardwareAuthToken* legacyToken) {
    legacyToken->challenge = hidlToken.challenge;
    legacyToken->user_id = hidlToken.userId;
    legacyToken->authenticator_id = hidlToken.authenticatorId;
    legacyToken->authenticator_type =
        static_cast<hw_authenticator_type_t>(hidlToken.authenticatorType);
    legacyToken->timestamp = hidlToken.timestamp;
    hidlVec2KmBlob(hidlToken.mac, &legacyToken->mac);
}

keymaster_key_param_set_t hidlKeyParams2Km(const hidl_vec<KeyParameter>& keyParams) {
    keymaster_key_param_set_t set;

    set.params = new keymaster_key_param_t[keyParams.size()];
    set.length = keyParams.size();

    for (size_t i = 0; i < keyParams.size(); ++i) {
        auto tag = legacy_enum_conversion(keyParams[i].tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            set.params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
            break;
        case KM_UINT:
        case KM_UINT_REP:
            set.params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            set.params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
            break;
        case KM_DATE:
            set.params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
            break;
        case KM_BOOL:
            if (keyParams[i].f.boolValue)
                set.params[i] = keymaster_param_bool(tag);
            else
                set.params[i].tag = KM_TAG_INVALID;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            set.params[i] =
                keymaster_param_blob(tag, &keyParams[i].blob[0], keyParams[i].blob.size());
            break;
        case KM_INVALID:
        default:
            set.params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }

    return set;
}

static inline hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set) {
    hidl_vec<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr) return result;

    result.resize(set.length);
    keymaster_key_param_t* params = set.params;
    for (size_t i = 0; i < set.length; ++i) {
        auto tag = params[i].tag;
        result[i].tag = legacy_enum_conversion(tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            result[i].f.integer = params[i].enumerated;
            break;
        case KM_UINT:
        case KM_UINT_REP:
            result[i].f.integer = params[i].integer;
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            result[i].f.longInteger = params[i].long_integer;
            break;
        case KM_DATE:
            result[i].f.dateTime = params[i].date_time;
            break;
        case KM_BOOL:
            result[i].f.boolValue = params[i].boolean;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            result[i].blob = std::vector<uint8_t>(params[i].blob.data,
                                                  params[i].blob.data + params[i].blob.data_length);
            break;
        case KM_INVALID:
        default:
            params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }
    return result;
}

class KmParamSet : public keymaster_key_param_set_t {
  public:
    explicit KmParamSet(const hidl_vec<KeyParameter>& keyParams)
        : keymaster_key_param_set_t(hidlKeyParams2Km(keyParams)) {}
    KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
        other.length = 0;
        other.params = nullptr;
    }
    KmParamSet(const KmParamSet&) = delete;
    ~KmParamSet() { delete[] params; }
};

static keymaster_error_t encodeParametersVerified(const VerificationToken& verificationToken,
                                                  std::vector<uint8_t>& asn1ParamsVerified) {
    if (verificationToken.parametersVerified.size() > 0) {
        AuthorizationSet paramSet;
        KeymasterBlob derBlob;
        UniquePtr<KM_AUTH_LIST, KM_AUTH_LIST_Delete> kmAuthList(KM_AUTH_LIST_new());

        paramSet.Reinitialize(KmParamSet(verificationToken.parametersVerified));

        auto err = build_auth_list(paramSet, kmAuthList.get());
        if (err != KM_ERROR_OK) {
            return err;
        }
        int len = i2d_KM_AUTH_LIST(kmAuthList.get(), nullptr);
        if (len < 0) {
            return TranslateLastOpenSslError();
        }

        if (!derBlob.Reset(len)) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }

        uint8_t* p = derBlob.writable_data();
        len = i2d_KM_AUTH_LIST(kmAuthList.get(), &p);
        if (len < 0) {
            return TranslateLastOpenSslError();
        }
        asn1ParamsVerified.insert(asn1ParamsVerified.begin(), p, p + len);
        derBlob.release();
    }
    return KM_ERROR_OK;
}

keymaster_error_t getOperationInfo(keymaster_purpose_t purpose, const AuthorizationSet& inParams,
                                   const AuthorizationSet& keyBlobParams, uint32_t& buferingMode,
                                   uint32_t& macLength) {
    BufferingMode bufMode = BufferingMode::NONE;
    keymaster_algorithm_t keyAlgo;
    keymaster_digest_t digest = KM_DIGEST_NONE;
    keymaster_padding_t padding = KM_PAD_NONE;
    keymaster_block_mode_t blockMode = KM_MODE_ECB;
    macLength = 0;
    if (!keyBlobParams.GetTagValue(TAG_ALGORITHM, &keyAlgo)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    inParams.GetTagValue(TAG_DIGEST, &digest);
    inParams.GetTagValue(TAG_PADDING, &padding);
    inParams.GetTagValue(TAG_BLOCK_MODE, &blockMode);
    inParams.GetTagValue(TAG_MAC_LENGTH, &macLength);
    macLength = (macLength / 8);
    switch (keyAlgo) {
    case KM_ALGORITHM_AES:
        if (purpose == KM_PURPOSE_ENCRYPT && padding == KM_PAD_PKCS7) {
            bufMode = BufferingMode::BUF_AES_ENCRYPT_PKCS7_BLOCK_ALIGNED;
        } else if (purpose == KM_PURPOSE_DECRYPT && padding == KM_PAD_PKCS7) {
            bufMode = BufferingMode::BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGNED;
        } else if (purpose == KM_PURPOSE_DECRYPT && blockMode == KM_MODE_GCM) {
            bufMode = BufferingMode::BUF_AES_GCM_DECRYPT_BLOCK_ALIGNED;
        }
        break;
    case KM_ALGORITHM_TRIPLE_DES:
        if (purpose == KM_PURPOSE_ENCRYPT && padding == KM_PAD_PKCS7) {
            bufMode = BufferingMode::BUF_DES_ENCRYPT_PKCS7_BLOCK_ALIGNED;
        } else if (purpose == KM_PURPOSE_DECRYPT && padding == KM_PAD_PKCS7) {
            bufMode = BufferingMode::BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGNED;
        }
        break;
    case KM_ALGORITHM_RSA:
        if (purpose == KM_PURPOSE_DECRYPT || digest == KM_DIGEST_NONE) {
            bufMode = BufferingMode::RSA_NO_DIGEST;
        }
        break;
    case KM_ALGORITHM_EC:
        if (digest == KM_DIGEST_NONE && purpose == KM_PURPOSE_SIGN) {
            bufMode = BufferingMode::EC_NO_DIGEST;
        }
        break;
    default:
        break;
    }
    buferingMode = static_cast<uint32_t>(bufMode);
    return KM_ERROR_OK;
}

}  // anonymous namespace

JavacardKeymaster4Device::JavacardKeymaster4Device(shared_ptr<JavacardKeymaster> jcImpl)
    : softKm_(new ::keymaster::AndroidKeymaster(
          []() -> auto{
              auto context = new JavaCardSoftKeymasterContext();
              context->SetSystemVersion(getOsVersion(), getOsPatchlevel());
              return context;
          }(),
          kOperationTableSize,
          keymaster::MessageVersion(keymaster::KmVersion::KEYMASTER_4_1, 0 /* km_date */))),
      jcImpl_(jcImpl) {
    std::shared_ptr<IJavacardSeResetListener> listener(
        dynamic_cast<IJavacardSeResetListener*>(this));
    jcImpl_->registerSeResetEventListener(listener);
}

JavacardKeymaster4Device::~JavacardKeymaster4Device() {}

// Methods from IKeymasterDevice follow.
Return<void> JavacardKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    uint64_t securityLevel = static_cast<uint64_t>(SecurityLevel::STRONGBOX);
    hidl_string jcKeymasterName;
    hidl_string jcKeymasterAuthor;
    string name;
    string author;
    auto [item, err] = jcImpl_->getHardwareInfo();
    if (err != KM_ERROR_OK || !cbor_.getUint64<uint64_t>(item, 1, securityLevel) ||
        !cbor_.getBinaryArray(item, 2, name) || !cbor_.getBinaryArray(item, 3, author)) {
        LOG(ERROR) << "Error in response of getHardwareInfo.";
        LOG(INFO) << "Returning defaultHwInfo in getHardwareInfo.";
        _hidl_cb(SecurityLevel::STRONGBOX, JAVACARD_KEYMASTER_NAME, JAVACARD_KEYMASTER_AUTHOR);
        return Void();
    }
    jcKeymasterName = name;
    jcKeymasterAuthor = author;
    _hidl_cb(static_cast<SecurityLevel>(securityLevel), jcKeymasterName, jcKeymasterAuthor);
    return Void();
}

Return<void>
JavacardKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
    HmacSharingParameters hmacSharingParameters;
    vector<uint8_t> nonce;
    vector<uint8_t> seed;
    auto err = jcImpl_->getHmacSharingParameters(&seed, &nonce);
    hmacSharingParameters.seed = seed;
    memcpy(hmacSharingParameters.nonce.data(), nonce.data(), nonce.size());
    // TODO
    // Send earlyBootEnded if there is any pending earlybootEnded event.
    // handleSendEarlyBootEndedEvent();
    _hidl_cb(legacy_enum_conversion(err), hmacSharingParameters);
    return Void();
}

Return<void>
JavacardKeymaster4Device::computeSharedHmac(const hidl_vec<HmacSharingParameters>& params,
                                            computeSharedHmac_cb _hidl_cb) {
    std::vector<uint8_t> secret;
    vector<::javacard_keymaster::HmacSharingParameters> reqParams(params.size());
    for (size_t i = 0; i < params.size(); i++) {
        reqParams[i].seed = params[i].seed;
        reqParams[i].nonce.insert(reqParams[i].nonce.end(), params[i].nonce.data(),
                                  params[i].nonce.data() + params[i].nonce.elementCount());
    }
    auto err = jcImpl_->computeSharedHmac(reqParams, &secret);
    // TODO
    // Send earlyBootEnded if there is any pending earlybootEnded event.
    // handleSendEarlyBootEndedEvent();
    _hidl_cb(legacy_enum_conversion(err), secret);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    auto err = jcImpl_->addRngEntropy(data);
    return legacy_enum_conversion(err);
}

Return<void> JavacardKeymaster4Device::generateKey(const hidl_vec<KeyParameter>& keyParams,
                                                   generateKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(keyParams));
    if (!paramSet.Contains(KM_TAG_CREATION_DATETIME) &&
        !paramSet.Contains(KM_TAG_ACTIVE_DATETIME)) {
        keymaster_key_param_t dateTime;
        dateTime.tag = KM_TAG_CREATION_DATETIME;
        dateTime.date_time = java_time(time(nullptr));
        paramSet.push_back(dateTime);
    }
    auto err = jcImpl_->generateKey(paramSet, &retKeyblob, &swEnforced, &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), retKeyblob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importKey(const hidl_vec<KeyParameter>& keyParams,
                                                 KeyFormat keyFormat,
                                                 const hidl_vec<uint8_t>& keyData,
                                                 importKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(keyParams));
    if (!paramSet.Contains(KM_TAG_CREATION_DATETIME) &&
        !paramSet.Contains(KM_TAG_ACTIVE_DATETIME)) {
        keymaster_key_param_t dateTime;
        dateTime.tag = KM_TAG_CREATION_DATETIME;
        dateTime.date_time = java_time(time(nullptr));
        paramSet.push_back(dateTime);
    }
    auto err = jcImpl_->importKey(paramSet, legacy_enum_conversion(keyFormat), keyData, &retKeyblob,
                                  &swEnforced, &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), retKeyblob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::importWrappedKey(
    const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob,
    const hidl_vec<uint8_t>& maskingKey, const hidl_vec<KeyParameter>& unwrappingParams,
    uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    vector<uint8_t> retKeyblob;
    paramSet.Reinitialize(KmParamSet(unwrappingParams));
    auto err = jcImpl_->keymasterImportWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey,
                                                  paramSet, passwordSid, biometricSid, &retKeyblob,
                                                  &swEnforced, &hwEnforced, &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), retKeyblob, keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest,
                                                 const hidl_vec<KeyParameter>& attestParams,
                                                 attestKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    vector<vector<uint8_t>> certChain;
    hidl_vec<hidl_vec<uint8_t>> outCertChain;
    paramSet.Reinitialize(KmParamSet(attestParams));
    auto err = jcImpl_->attestKey(keyToAttest, paramSet, &certChain);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "JavacardKeymaster4Device attestKey Failed in attestKey err: "
                   << (int32_t)err;
        _hidl_cb(legacy_enum_conversion(err), outCertChain);
        return Void();
    }
    err = jcImpl_->getCertChain(&certChain);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "JavacardKeymaster4Device attestKey Failed in getCertChain err: "
                   << (int32_t)err;
        _hidl_cb(legacy_enum_conversion(err), outCertChain);
        return Void();
    }
    outCertChain.resize(certChain.size());
    for (int i = 0; i < certChain.size(); i++) {
        outCertChain[i] = certChain[i];
    }
    _hidl_cb(legacy_enum_conversion(err), outCertChain);
    return Void();
}

Return<void> JavacardKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                                                  const hidl_vec<KeyParameter>& upgradeParams,
                                                  upgradeKey_cb _hidl_cb) {
    AuthorizationSet paramSet;
    paramSet.Reinitialize(KmParamSet(upgradeParams));
    vector<uint8_t> upgradedKeyBlob;
    auto err = jcImpl_->upgradeKey(keyBlobToUpgrade, paramSet, &upgradedKeyBlob);
    _hidl_cb(legacy_enum_conversion(err), upgradedKeyBlob);
    return Void();
}

Return<ErrorCode> JavacardKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    auto err = jcImpl_->deleteKey(keyBlob);
    return legacy_enum_conversion(err);
}

Return<ErrorCode> JavacardKeymaster4Device::deleteAllKeys() {
    auto err = jcImpl_->deleteAllKeys();
    return legacy_enum_conversion(err);
}

Return<ErrorCode> JavacardKeymaster4Device::destroyAttestationIds() {
    auto err = jcImpl_->destroyAttestationIds();
    return legacy_enum_conversion(err);
}

Return<void> JavacardKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                                             const hidl_vec<uint8_t>& clientId,
                                                             const hidl_vec<uint8_t>& appData,
                                                             getKeyCharacteristics_cb _hidl_cb) {
    AuthorizationSet swEnforced;
    AuthorizationSet hwEnforced;
    AuthorizationSet teeEnforced;
    auto err = jcImpl_->getKeyCharacteristics(keyBlob, clientId, appData, &swEnforced, &hwEnforced,
                                              &teeEnforced);
    KeyCharacteristics keyCharacteristics;
    keyCharacteristics.softwareEnforced = kmParamSet2Hidl(swEnforced);
    keyCharacteristics.hardwareEnforced = kmParamSet2Hidl(hwEnforced);
    _hidl_cb(legacy_enum_conversion(err), keyCharacteristics);
    return Void();
}

Return<void> JavacardKeymaster4Device::verifyAuthorization(uint64_t, const hidl_vec<KeyParameter>&,
                                                           const HardwareAuthToken&,
                                                           verifyAuthorization_cb _hidl_cb) {
    VerificationToken verificationToken;
    LOG(DEBUG) << "Verify authorizations UNIMPLEMENTED";
    _hidl_cb(ErrorCode::UNIMPLEMENTED, verificationToken);
    return Void();
}

Return<void> JavacardKeymaster4Device::exportKey(KeyFormat exportFormat,
                                                 const hidl_vec<uint8_t>& keyBlob,
                                                 const hidl_vec<uint8_t>& clientId,
                                                 const hidl_vec<uint8_t>& appData,
                                                 exportKey_cb _hidl_cb) {
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<uint8_t> resultKeyBlob;

    // Check if keyblob is corrupted
    getKeyCharacteristics(
        keyBlob, clientId, appData,
        [&](ErrorCode error, KeyCharacteristics /*keyCharacteristics*/) { errorCode = error; });

    if (errorCode != ErrorCode::OK) {
        LOG(ERROR) << "Error in exportKey: " << (int32_t)errorCode;
        _hidl_cb(errorCode, resultKeyBlob);
        return Void();
    }

    ExportKeyRequest request(softKm_->message_version());
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    ExportKeyResponse response(softKm_->message_version());
    softKm_->ExportKey(request, &response);

    if (response.error == KM_ERROR_INCOMPATIBLE_ALGORITHM) {
        // Symmetric Keys cannot be exported.
        response.error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        LOG(ERROR) << "error in exportKey: unsupported algorithm or key format";
    }
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    errorCode = legacy_enum_conversion(response.error);
    LOG(DEBUG) << "exportKey status: " << (int32_t)errorCode;
    _hidl_cb(errorCode, resultKeyBlob);
    return Void();
}

keymaster_error_t JavacardKeymaster4Device::handleBeginPublicKeyOperation(
    KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams,
    const HardwareAuthToken& authToken, hidl_vec<KeyParameter>& outParams,
    uint64_t& operationHandle, std::unique_ptr<JavacardKeymasterOperation>& operation) {
    BeginOperationRequest request(softKm_->message_version());
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));
    hidl_vec<uint8_t> hidl_vec_token = authToken2HidlVec(authToken);
    request.additional_params.push_back(
        TAG_AUTH_TOKEN, reinterpret_cast<uint8_t*>(hidl_vec_token.data()), hidl_vec_token.size());

    BeginOperationResponse response(softKm_->message_version());
    softKm_->BeginOperation(request, &response);
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD softkm BeginOperation status: "
               << (int32_t)response.error;
    if (response.error == KM_ERROR_OK) {
        outParams = kmParamSet2Hidl(response.output_params);
        operationHandle = response.op_handle;
        operation = std::make_unique<JavacardKeymasterOperation>(
            operationHandle, BufferingMode::NONE, 0, nullptr, OperationType::PUBLIC_OPERATION,
            softKm_);
    } else {
        LOG(ERROR) << "INS_BEGIN_OPERATION_CMD error in softkm BeginOperation status: "
                   << (int32_t)response.error;
    }
    return response.error;
}

keymaster_error_t JavacardKeymaster4Device::handleBeginPrivateKeyOperation(
    KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams,
    const HardwareAuthToken& authToken, hidl_vec<KeyParameter>& outParams,
    uint64_t& operationHandle, std::unique_ptr<JavacardKeymasterOperation>& operation) {
    AuthorizationSet paramSet;
    AuthorizationSet authSetParams;
    paramSet.Reinitialize(KmParamSet(inParams));
    ::keymaster::HardwareAuthToken legacyToken;
    legacyHardwareAuthToken(authToken, &legacyToken);
    auto err = jcImpl_->begin(legacy_enum_conversion(purpose), keyBlob, paramSet, legacyToken,
                              &authSetParams, operation);
    if (err == KM_ERROR_OK) {
        // Decode keyblob to get the BufferingMode and macLength properties.
        AuthorizationSet swEnforced;
        AuthorizationSet teeEnforced;
        AuthorizationSet hwEnforced;
        uint32_t bufMode;
        uint32_t macLength;
        auto [item, _] = cbor_.decodeKeyblob(keyBlob);
        if (item == nullptr) {
            return KM_ERROR_UNKNOWN_ERROR;
        }
        if (!cbor_.getKeyCharacteristics(item, kKeyblobKeyCharsOffset, swEnforced, hwEnforced,
                                         teeEnforced)) {
            return KM_ERROR_INVALID_KEY_BLOB;
        }
        err = getOperationInfo(static_cast<keymaster_purpose_t>(purpose), paramSet, hwEnforced,
                               bufMode, macLength);
        if (err != KM_ERROR_OK) {
            return err;
        }
        operation->setBufferingMode(static_cast<BufferingMode>(bufMode));
        operation->setMacLength(macLength);
        // Get the operation handle from the Operation.
        operationHandle = operation->getOpertionHandle();
        outParams = kmParamSet2Hidl(authSetParams);
    }
    return err;
}

keymaster_error_t JavacardKeymaster4Device::handleBeginOperation(
    KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob, const hidl_vec<KeyParameter>& inParams,
    const HardwareAuthToken& authToken, hidl_vec<KeyParameter>& outParams,
    uint64_t& operationHandle, OperationType& operType,
    std::unique_ptr<JavacardKeymasterOperation>& operation) {
    keymaster_error_t err = KM_ERROR_UNKNOWN_ERROR;
    if (operType == OperationType::PRIVATE_OPERATION) {
        err = handleBeginPrivateKeyOperation(purpose, keyBlob, inParams, authToken, outParams,
                                             operationHandle, operation);
        if (err == ExtendedErrors::PUBLIC_KEY_OPERATION) {
            // Handle public key operation.
            operType = OperationType::PUBLIC_OPERATION;
        }
    }

    if (operType == OperationType::PUBLIC_OPERATION) {
        err = handleBeginPublicKeyOperation(purpose, keyBlob, inParams, authToken, outParams,
                                            operationHandle, operation);
    }
    return err;
}

bool JavacardKeymaster4Device::isOperationHandleExists(uint64_t opHandle) {
    if (operationTable_.end() == operationTable_.find(opHandle)) {
        return false;
    }
    return true;
}

Return<void> JavacardKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& keyBlob,
                                             const hidl_vec<KeyParameter>& inParams,
                                             const HardwareAuthToken& authToken,
                                             begin_cb _hidl_cb) {
    uint64_t operationHandle = 0;
    OperationType operType = OperationType::PRIVATE_OPERATION;
    std::unique_ptr<JavacardKeymasterOperation> operation;
    hidl_vec<KeyParameter> outParams;
    LOG(DEBUG) << "INS_BEGIN_OPERATION_CMD purpose: " << (int32_t)purpose;
    auto err = handleBeginOperation(purpose, keyBlob, inParams, authToken, outParams,
                                    operationHandle, operType, operation);
    if (err == KM_ERROR_OK && isOperationHandleExists(operationHandle)) {
        LOG(DEBUG) << "Operation handle " << operationHandle
                   << "already exists"
                      "in the opertion table. so aborting this opertaion.";
        // abort the operation.
        err = abortOperation(operationHandle);
        if (err == KM_ERROR_OK) {
            // retry begin to get an another operation handle.
            err = handleBeginOperation(purpose, keyBlob, inParams, authToken, outParams,
                                       operationHandle, operType, operation);
            if (err == KM_ERROR_OK && isOperationHandleExists(operationHandle)) {
                err = KM_ERROR_UNKNOWN_ERROR;
                LOG(ERROR) << "INS_BEGIN_OPERATION_CMD: Failed in begin operation as the"
                              "operation handle already exists in the operation table."
                           << (int32_t)err;
                // abort the operation.
                auto abortErr = abortOperation(operationHandle);
                if (abortErr != KM_ERROR_OK) {
                    LOG(ERROR) << "Fail to abort the operation.";
                    err = abortErr;
                }
            }
        }
    }
    if (err == KM_ERROR_OK) {
        operationTable_[operationHandle] = std::move(operation);
    }
    _hidl_cb(legacy_enum_conversion(err), outParams, operationHandle);
    return Void();
}

keymaster_error_t JavacardKeymaster4Device::abortOperation(uint64_t operationHandle) {
    auto it = operationTable_.find(operationHandle);
    if (it == operationTable_.end()) {
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid "
                      "operation handle is passed or if"
                   << " secure element reset occurred.";
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    auto err = it->second->abort();
    if (err == KM_ERROR_OK) {
        /* Delete the entry on this operationHandle */
        operationTable_.erase(operationHandle);
    }
    return err;
}

Return<ErrorCode> JavacardKeymaster4Device::abort(uint64_t operationHandle) {
    return legacy_enum_conversion(abortOperation(operationHandle));
}

Return<void>
JavacardKeymaster4Device::update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                                 const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken,
                                 const VerificationToken& verificationToken, update_cb _hidl_cb) {
    hidl_vec<KeyParameter> outParams;
    AuthorizationSet authSetOutParams;
    uint32_t inputConsumed = 0;
    vector<uint8_t> output;
    vector<uint8_t> encodedVerificationToken;
    auto it = operationTable_.find(operationHandle);
    if (it == operationTable_.end()) {
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle "
                      "is passed or if"
                   << " secure element reset occurred.";
        _hidl_cb(ErrorCode::INVALID_OPERATION_HANDLE, inputConsumed, outParams, output);
        return Void();
    }
    AuthorizationSet paramSet;
    paramSet.Reinitialize(KmParamSet(inParams));
    ::keymaster::HardwareAuthToken legacyHwToken;
    legacyHardwareAuthToken(authToken, &legacyHwToken);
    auto err = encodeVerificationToken(verificationToken, &encodedVerificationToken);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "In update failed to encode VerificationToken" << (int32_t)err;
        _hidl_cb(legacy_enum_conversion(err), inputConsumed, outParams, output);
        return Void();
    }
    err = it->second->update(input, std::optional<AuthorizationSet>(paramSet), legacyHwToken,
                             encodedVerificationToken, &authSetOutParams, &inputConsumed, &output);
    if (err != KM_ERROR_OK) {
        /* Delete the entry on this operationHandle */
        operationTable_.erase(operationHandle);
    }
    outParams = kmParamSet2Hidl(authSetOutParams);
    _hidl_cb(legacy_enum_conversion(err), input.size(), outParams, output);
    return Void();
}

Return<void>
JavacardKeymaster4Device::finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                                 const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature,
                                 const HardwareAuthToken& authToken,
                                 const VerificationToken& verificationToken, finish_cb _hidl_cb) {
    hidl_vec<KeyParameter> outParams;
    AuthorizationSet authSetOutParams;
    vector<uint8_t> output;
    vector<uint8_t> encodedVerificationToken;
    auto it = operationTable_.find(operationHandle);
    if (it == operationTable_.end()) {
        LOG(ERROR) << " Operation handle is invalid. This could happen if invalid operation handle "
                      "is passed or if"
                   << " secure element reset occurred.";
        _hidl_cb(ErrorCode::INVALID_OPERATION_HANDLE, outParams, output);
        return Void();
    }
    AuthorizationSet paramSet;
    paramSet.Reinitialize(KmParamSet(inParams));
    ::keymaster::HardwareAuthToken legacyHwToken;
    legacyHardwareAuthToken(authToken, &legacyHwToken);
    auto err = encodeVerificationToken(verificationToken, &encodedVerificationToken);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "In finish failed to encode VerificationToken" << (int32_t)err;
        _hidl_cb(legacy_enum_conversion(err), outParams, output);
        return Void();
    }
    err =
        it->second->finish(input, std::optional<AuthorizationSet>(paramSet), signature,
                           legacyHwToken, encodedVerificationToken, {}, &authSetOutParams, &output);
    /* Delete the entry on this operationHandle */
    operationTable_.erase(operationHandle);
    outParams = kmParamSet2Hidl(authSetOutParams);
    _hidl_cb(legacy_enum_conversion(err), outParams, output);
    return Void();
}

// Methods from ::android::hardware::keymaster::V4_1::IKeymasterDevice follow.
Return<::android::hardware::keymaster::V4_1::ErrorCode>
JavacardKeymaster4Device::deviceLocked(bool passwordOnly,
                                       const VerificationToken& verificationToken) {
    vector<uint8_t> encodedVerificationToken;
    auto err = encodeVerificationToken(verificationToken, &encodedVerificationToken);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "In deviceLocked failed to encode VerificationToken" << (int32_t)err;
        return static_cast<V41ErrorCode>(err);
    }
    err = jcImpl_->deviceLocked(passwordOnly, encodedVerificationToken);
    return static_cast<V41ErrorCode>(err);
}

Return<::android::hardware::keymaster::V4_1::ErrorCode> JavacardKeymaster4Device::earlyBootEnded() {
    auto err = jcImpl_->earlyBootEnded();
    return static_cast<V41ErrorCode>(err);
}

keymaster_error_t
JavacardKeymaster4Device::encodeVerificationToken(const VerificationToken& verificationToken,
                                                  vector<uint8_t>* encodedToken) {
    vector<uint8_t> asn1ParamsVerified;
    auto err = encodeParametersVerified(verificationToken, asn1ParamsVerified);
    if (err != KM_ERROR_OK) {
        LOG(DEBUG) << "INS_DEVICE_LOCKED_CMD: Error in encodeParametersVerified, status: "
                   << (int32_t)err;
        return err;
    }
    cppbor::Array array;
    ::keymaster::VerificationToken token;
    token.challenge = verificationToken.challenge;
    token.timestamp = verificationToken.timestamp;
    token.security_level = legacy_enum_conversion(verificationToken.securityLevel);
    hidlVec2KmBlob(verificationToken.mac, &token.mac);
    cbor_.addVerificationToken(array, token, asn1ParamsVerified);
    *encodedToken = array.encode();
    return KM_ERROR_OK;
}

void JavacardKeymaster4Device::seResetEvent() {
    // clear strongbox entires.
    LOG(INFO)
        << "Secure Element reset or applet upgrade detected. Removing existing operation handles";
    auto it = operationTable_.begin();
    while (it != operationTable_.end()) {
        if (it->second->getOperationType() ==
            ::javacard_keymaster::OperationType::PRIVATE_OPERATION) {  // Strongbox operation
            LOG(INFO) << "operation handle: " << it->first << " is removed";
            it = operationTable_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
