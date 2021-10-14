/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "CborConverter.h"
#include "JavacardSecureElement.h"

#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>
#include <hardware/keymaster_defs.h>
#include <vector>

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8
#define RSA_BUFFER_SIZE 256
#define EC_BUFFER_SIZE 32
#define MAX_CHUNK_SIZE 256
namespace aidl::android::hardware::security::keymint {
using namespace ::keymint::javacard;
using ::ndk::ScopedAStatus;
using secureclock::TimeStampToken;
using std::optional;
using std::shared_ptr;
using std::string;
using std::vector;

// Bufferig modes for update
enum class BufferingMode : int32_t {
    NONE = 0,           // Send everything to javacard - most of the assymteric operations
    RSA_NO_DIGEST = 1,  // Buffer everything in update upto 256 bytes and send in finish. If
                        // input data is greater then 256 bytes then it is an error. Javacard
                        // will further check according to exact key size and crypto provider.
    EC_NO_DIGEST = 2,   // Buffer upto 65 bytes and then truncate. Javacard will further truncate
                        // upto exact keysize.
    BUF_AES_BLOCK_ALIGNED = 3,  // Buffer 15 bytes and reminder to make input data block aligned.
    BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGNED = 4, // Buffer 16 bytes.
    BUF_DES_BLOCK_ALIGNED = 5, // Buffer 7 bytes and reminder to make input data block aligned.
    BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGNED = 6, // Buffer 8 bytes.
    BUF_AES_GCM_DECRYPT_BLOCK_ALIGNED = 7, // Buffer 16 bytes.

};

// The is the view in the input data being processed by update/finish funcion.

struct DataView {
    vector<uint8_t> buffer;       // previously buffered data from cycle n-1
    const vector<uint8_t>& data;  // current data in cycle n.
    uint32_t start;               // start of the view
    size_t length;                // length of the view
};

class JavacardKeyMintOperation : public BnKeyMintOperation {
  public:
    explicit JavacardKeyMintOperation(keymaster_operation_handle_t opHandle,
                                      BufferingMode bufferingMode,
                                      uint16_t macLength,
                                      shared_ptr<JavacardSecureElement> card)
        : buffer_(vector<uint8_t>()), bufferingMode_(bufferingMode), macLength_(macLength),
          card_(card), opHandle_(opHandle)  {}
    virtual ~JavacardKeyMintOperation();

    ScopedAStatus updateAad(const vector<uint8_t>& input,
                            const optional<HardwareAuthToken>& authToken,
                            const optional<TimeStampToken>& timestampToken) override;

    ScopedAStatus update(const vector<uint8_t>& input, const optional<HardwareAuthToken>& authToken,
                         const optional<TimeStampToken>& timestampToken,
                         vector<uint8_t>* output) override;

    ScopedAStatus finish(const optional<vector<uint8_t>>& input,
                         const optional<vector<uint8_t>>& signature,
                         const optional<HardwareAuthToken>& authToken,
                         const optional<TimeStampToken>& timestampToken,
                         const optional<vector<uint8_t>>& confirmationToken,
                         vector<uint8_t>* output) override;

    ScopedAStatus abort() override;

  private:
    vector<uint8_t> popNextChunk(DataView& view, uint32_t chunkSize);

    keymaster_error_t updateInChunks(DataView& data, HardwareAuthToken& authToken,
                                     TimeStampToken& timestampToken, vector<uint8_t>* output);

    keymaster_error_t sendFinish(const vector<uint8_t>& data, const vector<uint8_t>& signature,
                                 const HardwareAuthToken& authToken,
                                 const TimeStampToken& timestampToken, vector<uint8_t>& output);

    keymaster_error_t sendUpdate(const vector<uint8_t>& data, const HardwareAuthToken& authToken,
                                 const TimeStampToken& timestampToken, vector<uint8_t>& output);

    inline void appendBufferedData(DataView& view) {
        if (!buffer_.empty()) {
            view.buffer = buffer_;
            view.length = view.length + buffer_.size();
            view.start = 0;
            // view.buffer = insert(data.begin(), buffer_.begin(), buffer_.end());
            buffer_.clear();
        }
    }

    std::tuple<std::unique_ptr<Item>, keymaster_error_t> sendRequest(Instruction ins,
                                                                     Array& request);
    keymaster_error_t bufferData(DataView& data);
    void blockAlign(DataView& data, uint16_t blockSize);
    uint16_t getDataViewOffset(DataView& view, uint16_t blockSize);

    vector<uint8_t> buffer_;
    BufferingMode bufferingMode_;
    uint16_t macLength_;
    const shared_ptr<JavacardSecureElement> card_;
    keymaster_operation_handle_t opHandle_;
    CborConverter cbor_;
};

}  // namespace aidl::android::hardware::security::keymint
