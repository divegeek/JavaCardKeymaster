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

#define LOG_TAG "javacard.keymint.device.strongbox-impl"
#include "JavacardSecureElement.h"
#include "keymint_utils.h"

#include <algorithm>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <iostream>
#include <iterator>
#include <keymaster/android_keymaster_messages.h>
#include <memory>
#include <regex.h>
#include <string>
#include <vector>

namespace keymint::javacard {

using namespace ::keymaster;
keymaster_error_t JavacardSecureElement::initializeJavacard() {
    Array request;
    request.add(Uint(getOsVersion()));
    request.add(Uint(getOsPatchlevel()));
    request.add(Uint(getVendorPatchlevel()));
    auto [item, err] = sendRequest(Instruction::INS_SET_BOOT_PARAMS_CMD, request);
    return err;
}

keymaster_error_t JavacardSecureElement::constructApduMessage(Instruction& ins,
                                                              std::vector<uint8_t>& inputData,
                                                              std::vector<uint8_t>& apduOut) {
    apduOut.push_back(static_cast<uint8_t>(APDU_CLS));  // CLS
    apduOut.push_back(static_cast<uint8_t>(ins));       // INS
    apduOut.push_back(static_cast<uint8_t>(APDU_P1));   // P1
    apduOut.push_back(static_cast<uint8_t>(APDU_P2));   // P2

    if (USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le
        // all set to 00. Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        // Extended length 3 bytes, starts with 0x00
        apduOut.push_back(static_cast<uint8_t>(0x00));
        if (inputData.size() > 0) {
            apduOut.push_back(static_cast<uint8_t>(inputData.size() >> 8));
            apduOut.push_back(static_cast<uint8_t>(inputData.size() & 0xFF));
            // Data
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        }
        // Expected length of output.
        // Accepting complete length of output every time.
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));
    } else {
        LOG(ERROR) << "Error in constructApduMessage.";
        return (KM_ERROR_INVALID_INPUT_LENGTH);
    }
    return (KM_ERROR_OK);  // success
}

keymaster_error_t JavacardSecureElement::sendData(Instruction ins, std::vector<uint8_t>& inData,
                                                  std::vector<uint8_t>& response) {
    keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
    std::vector<uint8_t> apdu;

    ret = constructApduMessage(ins, inData, apdu);

    if (ret != KM_ERROR_OK) {
        return ret;
    }

    if (!transport_->sendData(apdu, response)) {
        LOG(ERROR) << "Error in sending data in sendData.";
        return (KM_ERROR_SECURE_HW_COMMUNICATION_FAILED);
    }

    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU
    // status.
    if ((response.size() <= 2) || (getApduStatus(response) != APDU_RESP_STATUS_OK)) {
        LOG(ERROR) << "Response of the sendData is wrong: response size = " << response.size()
                   << " apdu status = " << getApduStatus(response);
        return (KM_ERROR_UNKNOWN_ERROR);
    }
    // remove the status bytes
    response.pop_back();
    response.pop_back();
    return (KM_ERROR_OK);  // success
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardSecureElement::sendRequest(Instruction ins, Array& request) {
    vector<uint8_t> response;
    // encode request
    std::vector<uint8_t> command = request.encode();
    auto sendError = sendData(ins, command, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardSecureElement::sendRequest(Instruction ins, std::vector<uint8_t>& command) {
    vector<uint8_t> response;
    auto sendError = sendData(ins, command, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardSecureElement::sendRequest(Instruction ins) {
    vector<uint8_t> response;
    vector<uint8_t> emptyRequest;
    auto sendError = sendData(ins, emptyRequest, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

}  // namespace keymint::javacard
