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

#include "JavacardKeymasterOperation.h"
#include <KMUtils.h>
#include <android-base/logging.h>

namespace javacard_keymaster {

keymaster_error_t JavacardKeymasterOperation::handleErrorCode(keymaster_error_t err) {
    // Check if secure element is reset
    uint32_t errorCode = static_cast<uint32_t>(0 - err);
    bool isSeResetOccurred = (0 != (errorCode & SE_POWER_RESET_STATUS_FLAG));

    if (isSeResetOccurred) {
        // Clear the operation table for Strongbox operations entries.
        if (seResetListener_) {
            seResetListener_->seResetEvent();
        }
        // Unmask the power reset status flag.
        errorCode &= ~SE_POWER_RESET_STATUS_FLAG;
    }
    return translateExtendedErrorsToHalErrors(static_cast<keymaster_error_t>(0 - errorCode));
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeymasterOperation::sendRequest(Instruction ins) {
    auto [item, err] = card_->sendRequest(ins);
    return {std::move(item), handleErrorCode(err)};
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardKeymasterOperation::sendRequest(Instruction ins, Array& request) {
    auto [item, err] = card_->sendRequest(ins, request);
    return {std::move(item), handleErrorCode(err)};
}

JavacardKeymasterOperation::~JavacardKeymasterOperation() {
    if (opHandle_ != 0) {
        abort();
    }
}

keymaster_error_t
JavacardKeymasterOperation::updateAad(const vector<uint8_t>& input,
                                      const HardwareAuthToken& authToken,
                                      const vector<uint8_t>& encodedVerificationToken) {
    cppbor::Array request;
    request.add(Uint(opHandle_));
    request.add(Bstr(input));
    cbor_.addHardwareAuthToken(request, authToken);
    request.add(EncodedItem(encodedVerificationToken));
    auto [_, err] = card_->sendRequest(Instruction::INS_UPDATE_AAD_OPERATION_CMD, request);
    return err;
}

keymaster_error_t JavacardKeymasterOperation::update(
    const vector<uint8_t>& input, const std::optional<AuthorizationSet>& inParams,
    const HardwareAuthToken& authToken, const vector<uint8_t>& encodedVerificationToken,
    AuthorizationSet* outParams, uint32_t* inputConsumed, vector<uint8_t>* output) {
    if (operType_ == OperationType::PUBLIC_OPERATION) {
        /* SW keymaster (Public key operation) */
        LOG(DEBUG) << "INS_UPDATE_OPERATION_CMD - swkm operation ";
        UpdateOperationResponse response(softKm_->message_version());
        UpdateOperationRequest request(softKm_->message_version());
        request.op_handle = opHandle_;
        request.input.Reinitialize(input.data(), input.size());
        request.additional_params.Reinitialize(inParams.value());

        softKm_->UpdateOperation(request, &response);
        LOG(DEBUG) << "INS_UPDATE_OPERATION_CMD - swkm update operation status: "
                   << (int32_t)response.error;
        if (response.error == KM_ERROR_OK) {
            *inputConsumed = response.input_consumed;
            *outParams = response.output_params;
            output->insert(output->end(), response.output.begin(), response.output.end());
        } else {
            LOG(ERROR) << "INS_UPDATE_OPERATION_CMD - error swkm update operation status: "
                       << (int32_t)response.error;
        }
        return response.error;
    } else {
        DataView view = {.buffer = {}, .data = input, .start = 0, .length = input.size()};
        keymaster_error_t err = bufferData(view);
        if (err != KM_ERROR_OK) {
            return err;
        }
        if (!(bufferingMode_ == BufferingMode::EC_NO_DIGEST ||
              bufferingMode_ == BufferingMode::RSA_NO_DIGEST)) {
            if (view.length > MAX_CHUNK_SIZE) {
                err = updateInChunks(view, inParams, authToken, encodedVerificationToken, output);
                if (err != KM_ERROR_OK) {
                    return err;
                }
            }
            vector<uint8_t> remaining = popNextChunk(view, view.length);
            err = sendUpdate(remaining, inParams, authToken, encodedVerificationToken, *output);
        }
        return err;
    }
}

keymaster_error_t JavacardKeymasterOperation::finish(
    const vector<uint8_t>& inData, const std::optional<AuthorizationSet>& inParams,
    const vector<uint8_t>& signature, const HardwareAuthToken& authToken,
    const vector<uint8_t>& encodedVerificationToken,
    const std::optional<vector<uint8_t>>& confToken, AuthorizationSet* outParams,
    vector<uint8_t>* output) {
    if (operType_ == OperationType::PUBLIC_OPERATION) {
        FinishOperationResponse response(softKm_->message_version());
        /* SW keymaster (Public key operation) */
        LOG(DEBUG) << "FINISH - swkm operation ";
        FinishOperationRequest request(softKm_->message_version());
        request.op_handle = opHandle_;
        request.input.Reinitialize(inData.data(), inData.size());
        request.signature.Reinitialize(signature.data(), signature.size());
        request.additional_params.Reinitialize(inParams.value());
        softKm_->FinishOperation(request, &response);
        LOG(DEBUG) << "FINISH - swkm operation, status: " << (int32_t)response.error;
        ;

        if (response.error == KM_ERROR_OK) {
            *outParams = response.output_params;
            output->insert(output->end(), response.output.begin(), response.output.end());
        } else {
            LOG(ERROR) << "Error in finish operation, status: " << (int32_t)response.error;
        }
        return response.error;
    } else {
        DataView view = {.buffer = {}, .data = inData, .start = 0, .length = inData.size()};
        appendBufferedData(view);
        if (!(bufferingMode_ == BufferingMode::EC_NO_DIGEST ||
              bufferingMode_ == BufferingMode::RSA_NO_DIGEST)) {
            if (view.length > MAX_CHUNK_SIZE) {
                auto err =
                    updateInChunks(view, inParams, authToken, encodedVerificationToken, output);
                if (err != KM_ERROR_OK) {
                    return err;
                }
            }
        }
        vector<uint8_t> remaining = popNextChunk(view, view.length);
        return sendFinish(remaining, inParams, signature, authToken, encodedVerificationToken,
                          confToken, *output);
    }
}

keymaster_error_t JavacardKeymasterOperation::abort() {
    if (operType_ == OperationType::PUBLIC_OPERATION) {
        AbortOperationRequest request(softKm_->message_version());
        request.op_handle = opHandle_;

        AbortOperationResponse response(softKm_->message_version());
        softKm_->AbortOperation(request, &response);
        return response.error;
        ;
    } else {
        Array request;
        request.add(Uint(opHandle_));
        auto [item, err] = sendRequest(Instruction::INS_ABORT_OPERATION_CMD, request);
        opHandle_ = 0;
        buffer_.clear();
        return err;
    }
}

void JavacardKeymasterOperation::blockAlign(DataView& view, uint16_t blockSize) {
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

uint16_t JavacardKeymasterOperation::getDataViewOffset(DataView& view, uint16_t blockSize) {
    uint16_t offset = 0;
    uint16_t remaining = 0;
    switch (bufferingMode_) {
    case BufferingMode::BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGNED:
    case BufferingMode::BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGNED:
        offset = ((view.length / blockSize)) * blockSize;
        remaining = (view.length % blockSize);
        if (offset >= blockSize && remaining == 0) {
            offset -= blockSize;
        }
        break;
    case BufferingMode::BUF_DES_ENCRYPT_PKCS7_BLOCK_ALIGNED:
    case BufferingMode::BUF_AES_ENCRYPT_PKCS7_BLOCK_ALIGNED:
        offset = ((view.length / blockSize)) * blockSize;
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

keymaster_error_t JavacardKeymasterOperation::bufferData(DataView& view) {
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
    case BufferingMode::BUF_AES_ENCRYPT_PKCS7_BLOCK_ALIGNED:
    case BufferingMode::BUF_AES_DECRYPT_PKCS7_BLOCK_ALIGNED:
        blockAlign(view, AES_BLOCK_SIZE);
        break;
    case BufferingMode::BUF_AES_GCM_DECRYPT_BLOCK_ALIGNED:
        blockAlign(view, macLength_);
        break;
    case BufferingMode::BUF_DES_ENCRYPT_PKCS7_BLOCK_ALIGNED:
    case BufferingMode::BUF_DES_DECRYPT_PKCS7_BLOCK_ALIGNED:
        blockAlign(view, DES_BLOCK_SIZE);
        break;
    case BufferingMode::NONE:
        break;
    }
    return KM_ERROR_OK;
}

// Incrementally send the request using multiple updates.
keymaster_error_t JavacardKeymasterOperation::updateInChunks(
    DataView& view, const std::optional<AuthorizationSet>& inParams,
    const HardwareAuthToken& authToken, const vector<uint8_t>& encodedVerificationToken,
    vector<uint8_t>* output) {
    keymaster_error_t sendError = KM_ERROR_UNKNOWN_ERROR;
    while (view.length > MAX_CHUNK_SIZE) {
        vector<uint8_t> chunk = popNextChunk(view, MAX_CHUNK_SIZE);
        sendError = sendUpdate(chunk, inParams, authToken, encodedVerificationToken, *output);
        if (sendError != KM_ERROR_OK) {
            return sendError;
        }
        // TODO Is it ok we clear tokens here.?
        // Clear tokens
        // if (!authToken.mac.empty()) authToken = HardwareAuthToken();
        // if (!timestampToken.mac.empty()) timestampToken = TimeStampToken();
    }
    return KM_ERROR_OK;
}

vector<uint8_t> JavacardKeymasterOperation::popNextChunk(DataView& view, uint32_t chunkSize) {
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

keymaster_error_t JavacardKeymasterOperation::sendUpdate(
    const vector<uint8_t>& input, const std::optional<AuthorizationSet>& inParams,
    const HardwareAuthToken& authToken, const vector<uint8_t>& encodedVerificationToken,
    vector<uint8_t>& output) {
    if (input.empty() && (!inParams.has_value() || !inParams->Contains(KM_TAG_ASSOCIATED_DATA))) {
        LOG(ERROR) << "JavacardKeymasterOperation::sendUpdate return no input to send";
        return KM_ERROR_OK;
    }
    cppbor::Array request;
    request.add(Uint(opHandle_));
    if (inParams.has_value()) cbor_.addKeyparameters(request, inParams.value());
    request.add(Bstr(input));
    cbor_.addHardwareAuthToken(request, authToken);
    request.add(EncodedItem(encodedVerificationToken));
    auto [item, error] = sendRequest(Instruction::INS_UPDATE_OPERATION_CMD, request);
    if (error != KM_ERROR_OK) {
        return error;
    }
    vector<uint8_t> respData;
    size_t size;
    error = cbor_.getArraySize(item, size);
    if ((error != KM_ERROR_OK) || !cbor_.getBinaryArray(item, size - 1, respData)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    output.insert(output.end(), respData.begin(), respData.end());
    return KM_ERROR_OK;
}

keymaster_error_t JavacardKeymasterOperation::sendFinish(
    const vector<uint8_t>& data, const std::optional<AuthorizationSet>& inParams,
    const vector<uint8_t>& sign, const HardwareAuthToken& authToken,
    const vector<uint8_t>& encodedVerificationToken,
    const std::optional<vector<uint8_t>>& confToken, vector<uint8_t>& output) {
    cppbor::Array request;
    request.add(Uint(opHandle_));
    if (inParams.has_value()) cbor_.addKeyparameters(request, inParams.value());
    request.add(Bstr(data));
    request.add(Bstr(sign));
    cbor_.addHardwareAuthToken(request, authToken);
    request.add(EncodedItem(encodedVerificationToken));
    if (confToken.has_value()) request.add(Bstr(confToken.value()));
    LOG(ERROR) << "JavacardKeymasterOperation::sendFinish step2";
    auto [item, err] = sendRequest(Instruction::INS_FINISH_OPERATION_CMD, request);
    if (err != KM_ERROR_OK) {
        return err;
    }
    vector<uint8_t> respData;
    size_t size;
    err = cbor_.getArraySize(item, size);
    if ((err != KM_ERROR_OK) || !cbor_.getBinaryArray(item, size - 1, respData)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    opHandle_ = 0;
    output.insert(output.end(), respData.begin(), respData.end());
    return KM_ERROR_OK;
}

}  // namespace javacard_keymaster
