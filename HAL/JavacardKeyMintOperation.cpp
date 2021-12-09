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

#define LOG_TAG "javacard.strongbox.keymint.operation-impl"

#include "JavacardKeyMintOperation.h"
#include <KeyMintUtils.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>
#include <android-base/logging.h>

namespace aidl::android::hardware::security::keymint {
using namespace ::keymint::javacard;
using secureclock::TimeStampToken;

JavacardKeyMintOperation::~JavacardKeyMintOperation() {
    if (opHandle_ != 0) {
        abort();
    }
}

ScopedAStatus JavacardKeyMintOperation::updateAad(const vector<uint8_t>& input,
                                                  const optional<HardwareAuthToken>& authToken,
                                                  const optional<TimeStampToken>& timestampToken) {
    cppbor::Array request;
    request.add(Uint(opHandle_));
    request.add(Bstr(input));
    cbor_.addHardwareAuthToken(request, authToken.value_or(HardwareAuthToken()));
    cbor_.addTimeStampToken(request, timestampToken.value_or(TimeStampToken()));
    auto [item, err] = card_->sendRequest(Instruction::INS_UPDATE_AAD_OPERATION_CMD, request);
    if (err != KM_ERROR_OK) {
        return km_utils::kmError2ScopedAStatus(err);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus JavacardKeyMintOperation::update(const vector<uint8_t>& input,
                                               const optional<HardwareAuthToken>& authToken,
                                               const optional<TimeStampToken>& timestampToken,
                                               vector<uint8_t>* output) {
    HardwareAuthToken aToken = authToken.value_or(HardwareAuthToken());
    TimeStampToken tToken = timestampToken.value_or(TimeStampToken());
    DataView view = {.buffer = {}, .data = input, .start = 0, .length = input.size()};
    keymaster_error_t err = bufferData(view);
    if (err != KM_ERROR_OK) {
        return km_utils::kmError2ScopedAStatus(err);
    }
    if (!(bufferingMode_ == BufferingMode::EC_NO_DIGEST ||
          bufferingMode_ == BufferingMode::RSA_NO_DIGEST)) {
        if (view.length > MAX_CHUNK_SIZE) {
            err = updateInChunks(view, aToken, tToken, output);
            if (err != KM_ERROR_OK) {
                return km_utils::kmError2ScopedAStatus(err);
            }
        }
        vector<uint8_t> remaining = popNextChunk(view, view.length);
        err = sendUpdate(remaining, aToken, tToken, *output);
    }
    return km_utils::kmError2ScopedAStatus(err);
}

ScopedAStatus JavacardKeyMintOperation::finish(
    const optional<vector<uint8_t>>& input, const optional<vector<uint8_t>>& signature,
    const optional<HardwareAuthToken>& authToken, const optional<TimeStampToken>& timestampToken,
    const optional<vector<uint8_t>>& /*confirmationToken*/, vector<uint8_t>* output) {
    HardwareAuthToken aToken = authToken.value_or(HardwareAuthToken());
    TimeStampToken tToken = timestampToken.value_or(TimeStampToken());
    const vector<uint8_t> inData = input.value_or(vector<uint8_t>());
    DataView view = {.buffer = {}, .data = inData, .start = 0, .length = inData.size()};
    const vector<uint8_t> sign = signature.value_or(vector<uint8_t>());
    appendBufferedData(view);
    if (!(bufferingMode_ == BufferingMode::EC_NO_DIGEST ||
          bufferingMode_ == BufferingMode::RSA_NO_DIGEST)) {
        if (view.length > MAX_CHUNK_SIZE) {
            auto err = updateInChunks(view, aToken, tToken, output);
            if (err != KM_ERROR_OK) {
                return km_utils::kmError2ScopedAStatus(err);
            }
        }
    }
    vector<uint8_t> remaining = popNextChunk(view, view.length);
    return km_utils::kmError2ScopedAStatus(sendFinish(remaining, sign, aToken, tToken, *output));
}

ScopedAStatus JavacardKeyMintOperation::abort() {
    Array request;
    request.add(Uint(opHandle_));
    auto [item, err] = card_->sendRequest(Instruction::INS_ABORT_OPERATION_CMD, request);
    opHandle_ = 0;
    buffer_.clear();
    return km_utils::kmError2ScopedAStatus(err);
}

void JavacardKeyMintOperation::blockAlign(DataView& view, uint16_t blockSize) {
    appendBufferedData(view);
    uint16_t offset = getDataViewOffset(view, blockSize);
    if (view.buffer.empty() && view.data.empty()) {
        offset = 0;
    } else if (view.buffer.empty()) {
        buffer_.insert(buffer_.end(), view.data.begin() + offset, view.data.end());
    } else if (view.data.empty()) {
        buffer_.insert(buffer_.end(), view.buffer.begin() + offset, view.buffer.end());
    } else {
        if (offset < view.buffer.size()) {
            buffer_.insert(buffer_.end(), view.buffer.begin() + offset, view.buffer.end());
            buffer_.insert(buffer_.end(), view.data.begin(), view.data.end());
        } else {
            offset = offset - view.buffer.size();
            buffer_.insert(buffer_.end(), view.data.begin() + offset, view.data.end());
        }
    }
    // adjust the view length by removing the buffered data size from it.
    view.length = view.length - buffer_.size();
}

uint16_t JavacardKeyMintOperation::getDataViewOffset(DataView& view, uint16_t blockSize) {
    uint16_t offset = 0;
    uint16_t remaining = 0;
    switch(bufferingMode_) {
        case BufferingMode::BUF_AES_BLOCK_ALIGNED:
        case BufferingMode::BUF_DES_BLOCK_ALIGNED:
        offset = ((view.length / blockSize)) * blockSize;
        break;
    case BufferingMode::BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGNED:
    case BufferingMode::BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGNED:
        offset = ((view.length / blockSize)) * blockSize;
        remaining = (view.length % blockSize);
        if (offset >= blockSize && remaining == 0) {
            offset -= blockSize;
        }
        break;
    case BufferingMode::BUF_AES_GCM_DECRYPT_BLOCK_ALIGNED:
        if (view.length > macLength_) {
            offset = (view.length - macLength_);
        }
        break;
    default:
        break;
    }
    return offset;
}

keymaster_error_t JavacardKeyMintOperation::bufferData(DataView& view) {
    if (view.data.empty()) return KM_ERROR_OK;  // nothing to buffer
    switch (bufferingMode_) {
    case BufferingMode::RSA_NO_DIGEST:
        buffer_.insert(buffer_.end(), view.data.begin(), view.data.end());
        if (buffer_.size() > RSA_BUFFER_SIZE) {
            abort();
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        view.start = 0;
        view.length = 0;
        break;
    case BufferingMode::EC_NO_DIGEST:
        if (buffer_.size() < EC_BUFFER_SIZE) {
            buffer_.insert(buffer_.end(), view.data.begin(), view.data.end());
            // Truncate the buffered data if greater then allowed EC buffer size.
            if (buffer_.size() > EC_BUFFER_SIZE) {
                buffer_.erase(buffer_.begin() + EC_BUFFER_SIZE, buffer_.end());
            }
        }
        view.start = 0;
        view.length = 0;
        break;
    case BufferingMode::BUF_AES_BLOCK_ALIGNED:
    case BufferingMode::BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGNED:
        blockAlign(view, AES_BLOCK_SIZE);
        break;
    case BufferingMode::BUF_AES_GCM_DECRYPT_BLOCK_ALIGNED:
        blockAlign(view, macLength_);
        break;
    case BufferingMode::BUF_DES_BLOCK_ALIGNED:
    case BufferingMode::BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGNED:
        blockAlign(view, DES_BLOCK_SIZE);
        break;
    case BufferingMode::NONE:
        break;
    }
    return KM_ERROR_OK;
}

// Incermentally send the request using multiple updates.
keymaster_error_t JavacardKeyMintOperation::updateInChunks(DataView& view,
                                                           HardwareAuthToken& authToken,
                                                           TimeStampToken& timestampToken,
                                                           vector<uint8_t>* output) {
    keymaster_error_t sendError = KM_ERROR_UNKNOWN_ERROR;
    while (view.length > MAX_CHUNK_SIZE) {
        vector<uint8_t> chunk = popNextChunk(view, MAX_CHUNK_SIZE);
        sendError = sendUpdate(chunk, authToken, timestampToken, *output);
        if (sendError != KM_ERROR_OK) {
            return sendError;
        }
        // Clear tokens
        if (!authToken.mac.empty()) authToken = HardwareAuthToken();
        if (!timestampToken.mac.empty()) timestampToken = TimeStampToken();
    }
    return KM_ERROR_OK;
}

vector<uint8_t> JavacardKeyMintOperation::popNextChunk(DataView& view, uint32_t chunkSize) {
    uint32_t start = view.start;
    uint32_t end = start + ((view.length < chunkSize) ? view.length : chunkSize);
    vector<uint8_t> chunk;
    if (start < view.buffer.size()) {
        if (end < view.buffer.size()) {
            chunk = {view.buffer.begin() + start, view.buffer.begin() + end};
        } else {
            end = end - view.buffer.size();
            chunk = {view.buffer.begin() + start, view.buffer.end()};
            chunk.insert(chunk.end(), view.data.begin(), view.data.begin() + end);
        }
    } else {
        start = start - view.buffer.size();
        end = end - view.buffer.size();
        chunk = {view.data.begin() + start, view.data.begin() + end};
    }
    view.start = view.start + chunk.size();
    view.length = view.length - chunk.size();
    return chunk;
}

keymaster_error_t JavacardKeyMintOperation::sendUpdate(const vector<uint8_t>& input,
                                                       const HardwareAuthToken& authToken,
                                                       const TimeStampToken& timestampToken,
                                                       vector<uint8_t>& output) {
    if (input.empty()) {
        return KM_ERROR_OK;
    }
    cppbor::Array request;
    request.add(Uint(opHandle_));
    request.add(Bstr(input));
    cbor_.addHardwareAuthToken(request, authToken);
    cbor_.addTimeStampToken(request, timestampToken);
    auto [item, error] = card_->sendRequest(Instruction::INS_UPDATE_OPERATION_CMD, request);
    if (error != KM_ERROR_OK) {
        return error;
    }
    vector<uint8_t> respData;
    if (!cbor_.getBinaryArray(item, 1, respData)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    output.insert(output.end(), respData.begin(), respData.end());
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeyMintOperation::sendFinish(const vector<uint8_t>& data,
                                                       const vector<uint8_t>& sign,
                                                       const HardwareAuthToken& authToken,
                                                       const TimeStampToken& timestampToken,
                                                       vector<uint8_t>& output) {
    cppbor::Array request;
    request.add(Uint(opHandle_));
    request.add(Bstr(data));
    request.add(Bstr(sign));
    cbor_.addHardwareAuthToken(request, authToken);
    cbor_.addTimeStampToken(request, timestampToken);
    auto [item, err] = card_->sendRequest(Instruction::INS_FINISH_OPERATION_CMD, request);
    if (err != KM_ERROR_OK) {
        return err;
    }
    vector<uint8_t> respData;
    if (!cbor_.getBinaryArray(item, 1, respData)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    opHandle_ = 0;
    output.insert(output.end(), respData.begin(), respData.end());
    return KM_ERROR_OK;
}

}  // namespace aidl::android::hardware::security::keymint
