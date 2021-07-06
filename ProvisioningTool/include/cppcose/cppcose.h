/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <cppbor/cppbor.h>
#include <cppbor/cppbor_parse.h>

namespace cppcose {

template <typename T> class ErrMsgOr;
using bytevec = std::vector<uint8_t>;

constexpr int kCoseSign1EntryCount = 4;
constexpr int kCoseSign1ProtectedParams = 0;
constexpr int kCoseSign1UnprotectedParams = 1;
constexpr int kCoseSign1Payload = 2;
constexpr int kCoseSign1Signature = 3;

constexpr int kCoseMac0EntryCount = 4;
constexpr int kCoseMac0ProtectedParams = 0;
constexpr int kCoseMac0UnprotectedParams = 1;
constexpr int kCoseMac0Payload = 2;
constexpr int kCoseMac0Tag = 3;

constexpr int kCoseEncryptEntryCount = 4;
constexpr int kCoseEncryptProtectedParams = 0;
constexpr int kCoseEncryptUnprotectedParams = 1;
constexpr int kCoseEncryptPayload = 2;
constexpr int kCoseEncryptRecipients = 3;

enum Label : int {
    ALGORITHM = 1,
    KEY_ID = 4,
    IV = 5,
    COSE_KEY = -1,
};

enum CoseKeyAlgorithm : int {
    AES_GCM_256 = 3,
    HMAC_256 = 5,
    ES256 = -7,  // ECDSA with SHA-256
    EDDSA = -8,
    ECDH_ES_HKDF_256 = -25,
};

enum CoseKeyCurve : int { P256 = 1, X25519 = 4, ED25519 = 6 };
enum CoseKeyType : int { OCTET_KEY_PAIR = 1, EC2 = 2, SYMMETRIC_KEY = 4 };
enum CoseKeyOps : int { SIGN = 1, VERIFY = 2, ENCRYPT = 3, DECRYPT = 4 };

constexpr int kAesGcmNonceLength = 12;
constexpr int kAesGcmTagSize = 16;
constexpr int kAesGcmKeySize = 32;
constexpr int kAesGcmKeySizeBits = 256;

template <typename T> class ErrMsgOr {
  public:
    ErrMsgOr(std::string errMsg)  // NOLINT(google-explicit-constructor)
        : errMsg_(std::move(errMsg)) {}
    ErrMsgOr(const char* errMsg)  // NOLINT(google-explicit-constructor)
        : errMsg_(errMsg) {}
    ErrMsgOr(T val)  // NOLINT(google-explicit-constructor)
        : value_(std::move(val)) {}

    explicit operator bool() const { return value_.has_value(); }

    T* operator->() & {
        assert(value_);
        return &value_.value();
    }
    T& operator*() & {
        assert(value_);
        return value_.value();
    };
    T&& operator*() && {
        assert(value_);
        return std::move(value_).value();
    };

    const std::string& message() { return errMsg_; }
    std::string moveMessage() { return std::move(errMsg_); }

    T moveValue() {
        assert(value_);
        return std::move(value_).value();
    }

  private:
    std::string errMsg_;
    std::optional<T> value_;
};

class CoseKey {
  public:
    CoseKey() {}
    CoseKey(const CoseKey&) = delete;
    CoseKey(CoseKey&&) = default;

    enum Label : int {
        KEY_TYPE = 1,
        KEY_ID = 2,
        ALGORITHM = 3,
        KEY_OPS = 4,
        CURVE = -1,
        PUBKEY_X = -2,
        PUBKEY_Y = -3,
        PRIVATE_KEY = -4,
        TEST_KEY = -70000  // Application-defined
    };

    static ErrMsgOr<CoseKey> parse(const bytevec& coseKey) {
        auto [parsedKey, _, errMsg] = cppbor::parse(coseKey);
        if (!parsedKey) return errMsg + " when parsing key";
        if (!parsedKey->asMap()) return "CoseKey must be a map";
        return CoseKey(static_cast<cppbor::Map*>(parsedKey.release()));
    }

    static ErrMsgOr<CoseKey> parse(const bytevec& coseKey, CoseKeyType expectedKeyType,
                                   CoseKeyAlgorithm expectedAlgorithm, CoseKeyCurve expectedCurve) {
        auto key = parse(coseKey);
        if (!key) return key;

        if (!key->checkIntValue(CoseKey::KEY_TYPE, expectedKeyType) ||
            !key->checkIntValue(CoseKey::ALGORITHM, expectedAlgorithm) ||
            !key->checkIntValue(CoseKey::CURVE, expectedCurve)) {
            return "Unexpected key type:";
        }

        return key;
    }
    static ErrMsgOr<CoseKey> parseP256(const bytevec& coseKey) {
        auto key = parse(coseKey, EC2, ES256, P256);
        if (!key) return key;

        auto& pubkey_x = key->getMap().get(PUBKEY_X);
        auto& pubkey_y = key->getMap().get(PUBKEY_Y);
        if (!pubkey_x || !pubkey_y || !pubkey_x->asBstr() || !pubkey_y->asBstr() ||
            pubkey_x->asBstr()->value().size() != 32 || pubkey_y->asBstr()->value().size() != 32) {
            return "Invalid P256 public key";
        }

        return key;
    }

    std::optional<int> getIntValue(Label label) {
        const auto& value = key_->get(label);
        if (!value || !value->asInt()) return {};
        return value->asInt()->value();
    }

    std::optional<bytevec> getBstrValue(Label label) {
        const auto& value = key_->get(label);
        if (!value || !value->asBstr()) return {};
        return value->asBstr()->value();
    }

    const cppbor::Map& getMap() const { return *key_; }
    cppbor::Map&& moveMap() { return std::move(*key_); }

    bool checkIntValue(Label label, int expectedValue) {
        const auto& value = key_->get(label);
        return value && value->asInt() && value->asInt()->value() == expectedValue;
    }

    void add(Label label, int value) { key_->add(label, value); }
    void add(Label label, bytevec value) { key_->add(label, std::move(value)); }

    bytevec encode() { return key_->canonicalize().encode(); }

  private:
    explicit CoseKey(cppbor::Map* parsedKey) : key_(parsedKey) {}

    // This is the full parsed key structure.
    std::unique_ptr<cppbor::Map> key_;
};

ErrMsgOr<bytevec> createCoseSign1Signature(const bytevec& key, const bytevec& protectedParams,
                                           const bytevec& payload, const bytevec& aad);
ErrMsgOr<cppbor::Array> constructCoseSign1(const bytevec& key, const bytevec& payload,
                                           const bytevec& aad);
ErrMsgOr<cppbor::Array> constructCoseSign1(const bytevec& key, cppbor::Map extraProtectedFields,
                                           const bytevec& payload, const bytevec& aad);
/**
 * Verify and parse a COSE_Sign1 message, returning the payload.
 *
 * @param ignoreSignature indicates whether signature verification should be skipped.  If true, no
 *        verification of the signature will be done.
 *
 * @param coseSign1 is the COSE_Sign1 to verify and parse.
 *
 * @param signingCoseKey is a CBOR-encoded COSE_Key to use to verify the signature.  The bytevec may
 *        be empty, in which case the function assumes that coseSign1's payload is the COSE_Key to
 *        use, i.e. that coseSign1 is a self-signed "certificate".
 */
ErrMsgOr<bytevec /* payload */> verifyAndParseCoseSign1(bool ignoreSignature,
                                                        const cppbor::Array* coseSign1,
                                                        const bytevec& signingCoseKey,
                                                        const bytevec& aad);
}  // namespace cppcose
