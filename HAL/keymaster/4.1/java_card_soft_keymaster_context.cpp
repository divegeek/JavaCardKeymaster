/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <java_card_soft_keymaster_context.h>

#include <memory>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/key_blob_utils/auth_encrypted_key_blob.h>
#include <keymaster/key_blob_utils/integrity_assured_key_blob.h>
#include <keymaster/key_blob_utils/ocb_utils.h>
#include <keymaster/key_blob_utils/software_keyblobs.h>
#include <keymaster/km_openssl/aes_key.h>
#include <keymaster/km_openssl/asymmetric_key.h>
#include <keymaster/km_openssl/attestation_utils.h>
#include <keymaster/km_openssl/ec_key_factory.h>
#include <keymaster/km_openssl/hmac_key.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <keymaster/km_openssl/rsa_key_factory.h>
#include <keymaster/km_openssl/soft_keymaster_enforcement.h>
#include <keymaster/km_openssl/triple_des_key.h>
#include <keymaster/logger.h>
#include <keymaster/operation.h>
#include <keymaster/wrapped_key.h>

#include <keymaster/contexts/soft_attestation_cert.h>
#include <CborConverter.h>
#include <iostream>
#include <climits>


using std::unique_ptr;

namespace keymaster {

JavaCardSoftKeymasterContext::JavaCardSoftKeymasterContext(keymaster_security_level_t security_level)
    : PureSoftKeymasterContext(security_level) {}

JavaCardSoftKeymasterContext::~JavaCardSoftKeymasterContext() {}

keymaster_error_t JavaCardSoftKeymasterContext::CreateKeyBlob(const AuthorizationSet& key_description,
                                                          const keymaster_key_origin_t origin,
                                                          const KeymasterKeyBlob& key_material,
                                                          KeymasterKeyBlob* blob,
                                                          AuthorizationSet* hw_enforced,
                                                          AuthorizationSet* sw_enforced) const {
    if (key_description.GetTagValue(TAG_ROLLBACK_RESISTANCE)) {
        return KM_ERROR_ROLLBACK_RESISTANCE_UNAVAILABLE;
    }

    keymaster_error_t error = SetKeyBlobAuthorizations(key_description, origin, os_version_,
                                                       os_patchlevel_, hw_enforced, sw_enforced);
    if (error != KM_ERROR_OK) return error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(key_description, &hidden, softwareRootOfTrust);
    if (error != KM_ERROR_OK) return error;
	
    size_t size = key_material.SerializedSize();

    if (!blob->Reset(size))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* p = blob->writable_data();
    p = key_material.Serialize(p, blob->end());
	
    return KM_ERROR_OK;
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

EVP_PKEY* RSA_fromMaterial(const uint8_t* modulus, size_t mod_size) {
    BIGNUM *n = BN_bin2bn(modulus, mod_size, NULL);
    BIGNUM *e = BN_new();//bignum_decode(exp, 5);
    char exp[] = "65537";
    BN_dec2bn(&e, exp);

   if (!n || !e)
    return NULL;

   if (e && n) {
       EVP_PKEY* pRsaKey = EVP_PKEY_new();
       RSA* rsa = RSA_new();
       rsa->e = e;
       rsa->n = n;
       EVP_PKEY_assign_RSA(pRsaKey, rsa);
       return pRsaKey;
   } else {
       if (n) BN_free(n);
       if (e) BN_free(e);
       return NULL;
   }
}

EC_GROUP* ChooseGroup(keymaster_ec_curve_t ec_curve) {
    switch (ec_curve) {
    case KM_EC_CURVE_P_224:
        return EC_GROUP_new_by_curve_name(NID_secp224r1);
        break;
    case KM_EC_CURVE_P_256:
        return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        break;
    case KM_EC_CURVE_P_384:
        return EC_GROUP_new_by_curve_name(NID_secp384r1);
        break;
    case KM_EC_CURVE_P_521:
        return EC_GROUP_new_by_curve_name(NID_secp521r1);
        break;
    default:
        return nullptr;
        break;
    }
}

EVP_PKEY* EC_fromMaterial(const uint8_t* pub_key, size_t key_size, keymaster_ec_curve_t ec_curve) {
    
    EC_GROUP *ec_group = ChooseGroup(ec_curve);
    EC_POINT *p = EC_POINT_new(ec_group);
    EC_KEY *ec_key = EC_KEY_new();
    EVP_PKEY *pEcKey = EVP_PKEY_new();

    if((EC_KEY_set_group(ec_key, ec_group) != 1) || (EC_POINT_oct2point(ec_group, p, pub_key, key_size, NULL) != 1)
        || (EC_KEY_set_public_key(ec_key, p) != 1) || (EVP_PKEY_set1_EC_KEY(pEcKey, ec_key) != 1)) {
        return NULL;
    }

    return pEcKey;
}

keymaster_error_t JavaCardSoftKeymasterContext::LoadKey(const keymaster_algorithm_t algorithm, KeymasterKeyBlob&& key_material,
                                                AuthorizationSet&& hw_enforced,
                                                AuthorizationSet&& sw_enforced,
                                                UniquePtr<Key>* key) const {
    auto factory = (AsymmetricKeyFactory*)GetKeyFactory(algorithm);
    UniquePtr<AsymmetricKey> asym_key;
    keymaster_error_t error = KM_ERROR_OK;
    const uint8_t* tmp = key_material.key_material;
    const size_t temp_size = key_material.key_material_size;
    EVP_PKEY* pkey = NULL;

    if(algorithm == KM_ALGORITHM_RSA) {
        pkey = RSA_fromMaterial(tmp, temp_size);
    } else if(algorithm == KM_ALGORITHM_EC) {
        keymaster_ec_curve_t ec_curve = KM_EC_CURVE_P_256;
        if (!hw_enforced.GetTagValue(TAG_EC_CURVE, &ec_curve) &&
            !sw_enforced.GetTagValue(TAG_EC_CURVE, &ec_curve)) {
            return KM_ERROR_INVALID_ARGUMENT;
        }//TODO also get ec_curve based on key size
        pkey = EC_fromMaterial(tmp, temp_size, ec_curve);
    }
    if (!pkey)
        return TranslateLastOpenSslError();
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey_deleter(pkey);

    error = factory->CreateEmptyKey(move(hw_enforced), move(sw_enforced), &asym_key);
    if (error != KM_ERROR_OK)
        return error;

    asym_key->key_material() = move(key_material);
    if (!asym_key->EvpToInternal(pkey))
        error = TranslateLastOpenSslError();
    else
        key->reset(asym_key.release());

    return error;
}

keymaster_error_t JavaCardSoftKeymasterContext::ParseKeyBlob(const KeymasterKeyBlob& blob,
                                                         const AuthorizationSet& /*additional_params*/,
                                                         UniquePtr<Key>* key) const {

    // The JavaCardSoftKeymasterContext handle a key blob generated by JavaCard keymaster for public key operations.
    //
    // 1.  A JavaCard keymaster key blob is a CborEncoded data of Secret, Nonce, AuthTag, KeyCharectristics and Public key.
    //     Here in public key operation we need only KeyCharectristics and Public key.
    //     Once these values extracted Public key is created based on parameters and returned.
    //

    AuthorizationSet hw_enforced;
    AuthorizationSet sw_enforced;
    KeymasterKeyBlob key_material;
    keymaster_error_t error;

    auto constructKey = [&, this] () mutable -> keymaster_error_t {
        keymaster_algorithm_t algorithm;
        if (!hw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm) &&
            !sw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm)) {
            return KM_ERROR_INVALID_ARGUMENT;
        }

        if (algorithm != KM_ALGORITHM_RSA && algorithm != KM_ALGORITHM_EC) {
            return KM_ERROR_INCOMPATIBLE_ALGORITHM;
        }
        error = LoadKey(algorithm, move(key_material), move(hw_enforced),
                                move(sw_enforced), key);
        return error;
    };

    CborConverter cc;
    std::unique_ptr<Item> item;
    ErrorCode errorCode = ErrorCode::UNKNOWN_ERROR;
    std::vector<uint8_t> cborKey(blob.key_material_size);
//    std::vector<uint8_t> cborKey(187);

    for(size_t i = 0; i < blob.key_material_size; i++) {
        cborKey[i] = blob.key_material[i];
    }
/*uint8_t tempBlob[] = {0x85, 0x58, 0x20, 0xDA, 0x29, 0xC7, 0x1A, 0x8C, 0xE7, 0x6A, 0x0D, 0xFD,
0x2E, 0x53, 0x06, 0x81, 0x85, 0x37, 0x2D, 0x9E, 0x74, 0xE7, 0xF1, 0xD5,
0x3F, 0x0E, 0xAB, 0x1A, 0xF8, 0xE9, 0x46, 0xFD, 0xDC, 0x37, 0x54, 0x4C,
0xE9, 0xA7, 0xD0, 0x71, 0x96, 0xCC, 0x66, 0x18, 0xF0, 0x53, 0xD1, 0x30,
0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x82, 0xA1, 0x1A, 0x30, 0x00, 0x01, 0xF5, 0x1A, 0x01, 0x02, 0x03,
0x04, 0xA6, 0x1A, 0x10, 0x00, 0x00, 0x02, 0x03, 0x1A, 0x50, 0x00, 0x00,
0xC8, 0x1A, 0x00, 0x01, 0x00, 0x01, 0x1A, 0x30, 0x00, 0x00, 0x03, 0x19,
0x01, 0x00, 0x1A, 0x10, 0x00, 0x02, 0xBE, 0x00, 0x1A, 0x30, 0x00, 0x02,
0xC1, 0x00, 0x1A, 0x30, 0x00, 0x02, 0xC2, 0x1A, 0x00, 0x03, 0x15, 0x14,
0x58, 0x41, 0x04, 0x2B, 0xF1, 0x84, 0xD4, 0xFB, 0x63, 0x44, 0x20, 0xD0,
0xA3, 0x7D, 0x6A, 0xC1, 0xC5, 0x26, 0x12, 0xCD, 0x79, 0x77, 0x81, 0x22,
0x33, 0x30, 0x70, 0xF7, 0x25, 0x6D, 0x75, 0xE0, 0xD4, 0xD0, 0x50, 0xD6,
0x80, 0x65, 0x2A, 0x44, 0x0B, 0x8E, 0xFC, 0xA0, 0x8B, 0xC5, 0xF4, 0x8A,
0xCA, 0x4B, 0x89, 0x6E, 0x8B, 0xFC, 0x38, 0xB7, 0xC9, 0xB9, 0xB6, 0xE7,
0x57, 0xE6, 0x53, 0xE9, 0xBF, 0x94, 0x3A};
    for(size_t i = 0; i < 187; i++) {
        cborKey[i] = tempBlob[i];
    }
*/    
    std::tie(item, errorCode) = cc.decodeData(cborKey, false);
    if (item != nullptr) {
        std::vector<uint8_t> temp;
        cc.getBinaryArray(item, 4, temp);

        key_material = {temp.data(), temp.size()};
        temp.clear();
        KeyCharacteristics keyCharacteristics;
        cc.getKeyCharacteristics(item, 3, keyCharacteristics);

        sw_enforced.Reinitialize(KmParamSet(keyCharacteristics.softwareEnforced));
        hw_enforced.Reinitialize(KmParamSet(keyCharacteristics.hardwareEnforced));
    }
    return constructKey();
}
}  // namespace keymaster
