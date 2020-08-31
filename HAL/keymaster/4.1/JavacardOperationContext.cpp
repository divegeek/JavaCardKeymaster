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

#include <JavacardOperationContext.h>
#include <algorithm>

#define MAX_ALLOWED_INPUT_SIZE 512
#define AES_BLOCK_SIZE          16
#define DES_BLOCK_SIZE           8
#define RSA_INPUT_MSG_LEN      256
#define EC_INPUT_MSG_LEN        32
#define MAX_RSA_BUFFER_SIZE    256
#define MAX_EC_BUFFER_SIZE      32

namespace keymaster {
namespace V4_1 {
namespace javacard {

enum class Operation {
    Update = 0,
    Finish = 1
};

inline ErrorCode hidlParamSet2OperatinInfo(const hidl_vec<KeyParameter>& params, OperationInfo& info) {
    for(int i = 0; i < params.size(); i++) {
        const KeyParameter &param = params[i];
        switch(param.tag) {
            case Tag::ALGORITHM:
                info.alg = static_cast<Algorithm>(param.f.integer);
                break;
            case Tag::DIGEST:
                info.digest = static_cast<Digest>(param.f.integer);
                break;
            case Tag::PADDING:
                info.pad = static_cast<PaddingMode>(param.f.integer);
                break;
            case Tag::BLOCK_MODE:
                info.mode = static_cast<BlockMode>(param.f.integer);
                break;
            default:
                continue;
        }
    }
    return ErrorCode::OK;
}

ErrorCode OperationContext::setOperationInfo(uint64_t operationHandle, KeyPurpose purpose, Algorithm alg,
        const hidl_vec<KeyParameter>& params) {
    ErrorCode errorCode = ErrorCode::OK;
    OperationData data;
    if(ErrorCode::OK != (errorCode = hidlParamSet2OperatinInfo(params, data.info))) {
        return errorCode;
    }
    data.info.purpose = purpose;
    data.info.alg = alg;
    memset((void*)&(data.data), 0x00, sizeof(data.data));
    operationTable[operationHandle] = data;
    return ErrorCode::OK;
}

ErrorCode OperationContext::clearOperationData(uint64_t operHandle) {
    size_t size = operationTable.erase(operHandle);
    if(!size) 
        return  ErrorCode::INVALID_OPERATION_HANDLE;
    else 
        return ErrorCode::OK;
}

ErrorCode OperationContext::validateInputData(uint64_t operHandle, Operation opr,
        const std::vector<uint8_t>& actualInput, std::vector<uint8_t>& input) {
    ErrorCode errorCode = ErrorCode::OK;

    OperationData& oprData = operationTable[operHandle];

    if(KeyPurpose::SIGN == oprData.info.purpose) {
        if(Algorithm::RSA == oprData.info.alg && Digest::NONE == oprData.info.digest) {
            if((oprData.data.buf_len+actualInput.size()) > RSA_INPUT_MSG_LEN)
                return ErrorCode::INVALID_INPUT_LENGTH;
        } else if(Algorithm::EC == oprData.info.alg && Digest::NONE == oprData.info.digest) {
            /* Silently truncate the input */
            if(oprData.data.buf_len >= EC_INPUT_MSG_LEN) {
                return ErrorCode::OK;
            } else if(actualInput.size()+oprData.data.buf_len > EC_INPUT_MSG_LEN) {
                for(int i=oprData.data.buf_len,j=0; i < EC_INPUT_MSG_LEN; ++i,++j) {
                    input.push_back(actualInput[j]);
                }
                return ErrorCode::OK;
            }
        }
    }

    if(KeyPurpose::DECRYPT == oprData.info.purpose && Algorithm::RSA == oprData.info.alg) {
        if((oprData.data.buf_len+actualInput.size()) > MAX_RSA_BUFFER_SIZE) {
            return ErrorCode::INVALID_INPUT_LENGTH;
        }
    }

    if(opr == Operation::Finish) {
        //If it is observed in finish operation that buffered data + input data exceeds the MAX_ALLOWED_INPUT_SIZE then
        //combine both the data in a single buffer. This helps in making sure that no data is left out in the buffer after
        //finish opertion.
        if((oprData.data.buf_len+actualInput.size()) > MAX_ALLOWED_INPUT_SIZE) {
            for(size_t i = 0; i < oprData.data.buf_len; ++i) {
                input.push_back(oprData.data.buf[i]);
            }
            input.insert(input.end(), actualInput.begin(), actualInput.end());
            //As buffered data is already consumed earse the buffer.
            if(oprData.data.buf_len != 0) {
                memset(oprData.data.buf, 0x00, sizeof(oprData.data.buf));
                oprData.data.buf_len = 0;
            }
        }
    }
    input = actualInput;
    return errorCode;
}

ErrorCode OperationContext::update(uint64_t operHandle, const std::vector<uint8_t>& actualInput,
        sendDataToSE_cb cb) {
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> input;

    /* Validate the input data */
    if(ErrorCode::OK != (errorCode = validateInputData(operHandle, Operation::Update, actualInput, input))) {
        return errorCode;
    }

    if (input.size() > MAX_ALLOWED_INPUT_SIZE) {
        int noOfChunks = input.size()/MAX_ALLOWED_INPUT_SIZE;
        int extraData = input.size()%MAX_ALLOWED_INPUT_SIZE;
        for(int i =0 ; i < noOfChunks; i++) {
            auto first = input.cbegin() + (i*MAX_ALLOWED_INPUT_SIZE);
            auto end = first + MAX_ALLOWED_INPUT_SIZE;
            std::vector<uint8_t> newInput(first, end);
            if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, newInput.data(), newInput.size(),
                            Operation::Update, cb))) {
                return errorCode;
            }
        }
        if(extraData > 0) {
            std::vector<uint8_t> finalInput(input.cend()-extraData, input.cend());
            if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, finalInput.data(), finalInput.size(), 
                            Operation::Update, cb))) {
                return errorCode;
            }
        }
    } else {
        if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, input.data(), input.size(), 
                        Operation::Update, cb))) {
            return errorCode;
        }
    }
    return errorCode;
}

ErrorCode OperationContext::finish(uint64_t operHandle, const std::vector<uint8_t>& actualInput, sendDataToSE_cb cb) {
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> input;

    /* Validate the input data */
    if(ErrorCode::OK != (errorCode = validateInputData(operHandle, Operation::Finish, actualInput, input))) {
        return errorCode;
    }

    if (input.size() > MAX_ALLOWED_INPUT_SIZE) {
        int noOfChunks = input.size()/MAX_ALLOWED_INPUT_SIZE;
        int extraData = input.size()%MAX_ALLOWED_INPUT_SIZE;
        for(int i =0 ; i < noOfChunks; i++) {
            auto first = input.cbegin() + (i*MAX_ALLOWED_INPUT_SIZE);
            auto end = first + MAX_ALLOWED_INPUT_SIZE;
            std::vector<uint8_t> newInput(first, end);
            if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, newInput.data(), newInput.size(),
                            Operation::Update, cb))) {
                return errorCode;
            }
        }
        if(extraData > 0) {
            std::vector<uint8_t> finalInput(input.cend()-extraData, input.cend());
            if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, finalInput.data(), finalInput.size(), 
                            Operation::Finish, cb, true))) {
                return errorCode;
            }
        }
    } else {
        if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, input.data(), input.size(), 
                        Operation::Finish, cb, true))) {
            return errorCode;
        }
    }
    return errorCode;
}

/* This function is called for only Symmetric operations */
ErrorCode OperationContext::getBlockAlignedData(uint64_t operHandle, uint8_t* input, size_t input_len,
        Operation opr, std::vector<uint8_t>& out) {
    size_t dataToSELen = 0;
    size_t inputConsumed = 0;/*Length of the data consumed from input */
    size_t blockSize = 0;
    BufferedData& data = operationTable[operHandle].data;
    int bufIndex = data.buf_len;

    if(Algorithm::AES == operationTable[operHandle].info.alg) {
        blockSize = AES_BLOCK_SIZE;
    } else if(Algorithm::TRIPLE_DES == operationTable[operHandle].info.alg) {
        blockSize = DES_BLOCK_SIZE;
    }

    if(opr == Operation::Finish) {
        //Copy the buffer to be send to SE.
        for(int i = 0; i < data.buf_len; i++)
        {
            out.push_back(data.buf[i]);
        }
        dataToSELen = data.buf_len + input_len;
    } else {
        /*Update */
        //Calculate the block sized length on combined input of both buffered data and input data.
        size_t blockAlignedLen = ((data.buf_len + input_len)/blockSize) * blockSize;
        //For symmetric ciphers, decryption operation and PKCS7 padding mode or AES GCM operation save the last 16 bytes
        //of block and send this block in finish operation. This is done to make sure that there will be always a 16
        //bytes of data left for finish operation so that javacard Applet may remove PKCS7 padding if any or get the tag
        //data for AES GCM operation for authentication purpose.
        if(((operationTable[operHandle].info.alg == Algorithm::AES) || 
                    (operationTable[operHandle].info.alg == Algorithm::TRIPLE_DES)) &&
                (operationTable[operHandle].info.pad == PaddingMode::PKCS7 ||
                 operationTable[operHandle].info.mode == BlockMode::GCM) &&
                (operationTable[operHandle].info.purpose == KeyPurpose::DECRYPT)) {
            if(blockAlignedLen >= blockSize) blockAlignedLen -= blockSize;
        }
        //Copy data to be send to SE from buffer, only if atleast a minimum block aligned size is available.
        if(blockAlignedLen >= blockSize) {
            for(size_t pos = 0; pos < std::min(blockAlignedLen, data.buf_len); pos++) {
                out.push_back(data.buf[pos]);
            }
        }
        dataToSELen = blockAlignedLen;
    }

    if(dataToSELen > 0) {
        //If buffer length is greater than the data length to be send to SE, then input data consumed is 0.
        //That means all the data to be send to SE is consumed from the buffer.
        inputConsumed = (data.buf_len > dataToSELen) ? 0 : (dataToSELen - data.buf_len);

        //Copy the buffer to be send to SE.
        for(int i = 0; i < inputConsumed; i++)
        {
            out.push_back(input[i]);
        }

        if(data.buf_len > dataToSELen) {
            //Only blockAlignedLen data is consumed from buffer so reorder the buffer data.
            memcpy(data.buf, data.buf+dataToSELen, data.buf_len-dataToSELen);
            memset(data.buf+dataToSELen, 0x00, data.buf_len-dataToSELen);
            data.buf_len -= dataToSELen;
            bufIndex = data.buf_len;
        } else {
            // All the data is consumed so clear buffer
            if(data.buf_len != 0) {
                memset(data.buf, 0x00, sizeof(data.buf));
                bufIndex = data.buf_len = 0;
            }
        }
    }

    //Store the remaining buffer for later use.
    data.buf_len += (input_len - inputConsumed);
    for(int i = 0; i < (input_len - inputConsumed); i++)
    {
        data.buf[bufIndex+i] = input[inputConsumed+i];
    }
    return ErrorCode::OK;
}

ErrorCode OperationContext::handleInternalUpdate(uint64_t operHandle, uint8_t* data, size_t len, Operation opr,
        sendDataToSE_cb cb, bool finish) {
    ErrorCode errorCode = ErrorCode::OK;
    std::vector<uint8_t> out;

    if(Algorithm::AES == operationTable[operHandle].info.alg ||
            Algorithm::TRIPLE_DES == operationTable[operHandle].info.alg) {
        /*Symmetric */
        if(ErrorCode::OK != (errorCode = getBlockAlignedData(operHandle, data, len,
                        opr, out))) {
            return errorCode;
        }
        //Call the callback under these condition
        //1. if it is a finish operation.
        //2. if there is some data to be send to Javacard.(either update or finish operation).
        //3. if the operation is GCM Mode. Even though there is no data to be send there could be AAD data to be sent to
        //javacard.
        if(finish || out.size() > 0 || BlockMode::GCM == operationTable[operHandle].info.mode) {
            if(ErrorCode::OK != (errorCode = cb(out, finish))) {
                return errorCode;
            }
        }
    } else {
        /* Asymmetric */
        if(operationTable[operHandle].info.purpose == KeyPurpose::DECRYPT ||
                operationTable[operHandle].info.digest == Digest::NONE) {
            //In case of Decrypt operation or Sign operation with no digest case, buffer the data in
            //update call and send it to SE in finish call.
            if(finish) {
                //If finish flag is true all the data has to be sent to javacard.
                size_t i = 0;
                for(; i < operationTable[operHandle].data.buf_len; ++i) {
                    out.push_back(operationTable[operHandle].data.buf[i]);
                }
                for(i = 0; i < len; ++i) {
                    out.push_back(data[i]);
                }
                //As buffered data is already consumed earse the buffer.
                if(operationTable[operHandle].data.buf_len != 0) {
                    memset(operationTable[operHandle].data.buf, 0x00, sizeof(operationTable[operHandle].data.buf));
                    operationTable[operHandle].data.buf_len = 0;
                }
                if(ErrorCode::OK != (errorCode = cb(out, finish))) {
                    return errorCode;
                }
            } else {
                //For strongbox keymaster, in NoDigest case the length of the input message for RSA should be more than
                //256 and for EC it should not be more than 32. This validation is already happening in
                //validateInputData function. Just for safety sake we are checking the length to MAX_BUF_SIZE.
                if(operationTable[operHandle].data.buf_len <= MAX_BUF_SIZE) {
                    size_t bufIndex = operationTable[operHandle].data.buf_len;
                    size_t pos = 0;
                    for(; (pos < len) && (pos < (MAX_BUF_SIZE-bufIndex)); pos++)
                    {
                        operationTable[operHandle].data.buf[bufIndex+pos] = data[pos];
                    }
                    operationTable[operHandle].data.buf_len += pos;
                }
            }
        } else { /* With Digest */
            for(size_t j=0; j < len; ++j)
            {
                out.push_back(data[j]);
            }
            //if len=0, then no need to call the callback, since there is no information to be send to javacard,
            // but if finish flag is true irrespective of length the callback should be called.
            if(len != 0 || finish) {
                if(ErrorCode::OK != (errorCode = cb(out, finish))) {
                    return errorCode;
                }
            }
        }
    }
    return errorCode;
}


}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
