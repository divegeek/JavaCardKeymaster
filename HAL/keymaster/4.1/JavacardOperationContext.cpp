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

#define MAX_ALLOWED_INPUT_SIZE 512
#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE  8

namespace keymaster {
namespace V4_1 {
namespace javacard {

enum class Operation {
    Update = 0,
    Finish = 1
};

struct BufferedData {
    uint8_t buf[MAX_BUF_SIZE];
    int buf_len;
};

struct OperationData {
    OperationInfo info;
    BufferedData data;
};


ErrorCode OperationContext::setOperationData(uint64_t operationHandle, OperationInfo& operInfo) {
    OperationData data;
    data.info = operInfo;
    operationTable[operationHandle] = data;
    return ErrorCode::OK;
}

ErrorCode OperationContext::getOperationData(uint64_t operHandle, OperationInfo& operInfo) {
    auto itr = operationTable.find(operHandle);
    if(itr != operationTable.end()) {
        operInfo = itr->second.info;
        return ErrorCode::OK;
    }
    return ErrorCode::INVALID_OPERATION_HANDLE;
}

ErrorCode OperationContext::clearOperationData(uint64_t operHandle) {
    size_t size = operationTable.erase(operHandle);
    if(!size) 
        return  ErrorCode::INVALID_OPERATION_HANDLE;
    else 
        return ErrorCode::OK;
}

ErrorCode OperationContext::update(uint64_t operHandle, std::vector<uint8_t>& input, sendDataToSE_cb cb) {
    ErrorCode errorCode = ErrorCode::OK;
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

ErrorCode OperationContext::finish(uint64_t operHandle, std::vector<uint8_t>& input, sendDataToSE_cb cb) {
    ErrorCode errorCode = ErrorCode::OK;
    if (input.size() > MAX_ALLOWED_INPUT_SIZE) {
        int noOfChunks = input.size()/MAX_ALLOWED_INPUT_SIZE;
        int extraData = input.size()%MAX_ALLOWED_INPUT_SIZE;
        for(int i =0 ; i < noOfChunks; i++) {
            auto first = input.cbegin() + (i*MAX_ALLOWED_INPUT_SIZE);
            auto end = first + MAX_ALLOWED_INPUT_SIZE;
            std::vector<uint8_t> newInput(first, end);
            if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, newInput.data(), newInput.size(),
                Operation::Finish, cb))) {
                return errorCode;
            }
        }
        if(extraData > 0) {
            std::vector<uint8_t> finalInput(input.cend()-extraData, input.cend());
            if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, finalInput.data(), finalInput.size(), 
                Operation::Finish, cb))) {
                return errorCode;
            }
        }
    } else {
        if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, input.data(), input.size(), 
            Operation::Finish, cb))) {
            return errorCode;
        }
    }
    return errorCode;
}

ErrorCode OperationContext::internalUpdate(uint64_t operHandle, uint8_t* input, size_t input_len, Operation opr, std::vector<uint8_t>& out) {
    int dataToSELen=0;
    /*Length of the data consumed from input */
    int inputConsumed=0;
    bool dataSendToSE = true;
    int blockSize = 0;
    BufferedData data = operationTable[operHandle].data;
    int bufIndex = data.buf_len;

    if(Algorithm::AES == operationTable[operHandle].info.alg) {
        blockSize = AES_BLOCK_SIZE;
    } else if(Algorithm::TRIPLE_DES == operationTable[operHandle].info.alg) {
        blockSize = DES_BLOCK_SIZE;
    }

    if(data.buf_len > 0) {
        if(opr == Operation::Finish) {
            //Copy the buffer to be send to SE.
            for(int i = 0; i < data.buf_len; i++)
            {
                out.push_back(data.buf[i]);
            }
            dataToSELen = data.buf_len + input_len;
        } else {
            if (data.buf_len + input_len >= blockSize) {
                dataToSELen = data.buf_len + input_len;
                //Copy the buffer to be send to SE.
                for(int i = 0; i < data.buf_len; i++)
                {
                    out.push_back(data.buf[i]);
                }
            } else {
                dataSendToSE = false;
            }     
        }
    } else {
        dataToSELen = input_len;
    }

    if(dataSendToSE) {
        if(opr == Operation::Update) {
            dataToSELen = (dataToSELen/blockSize) * blockSize;
        }
        inputConsumed = dataToSELen - data.buf_len;

        //Copy the buffer to be send to SE.
        for(int i = 0; i < inputConsumed; i++)
        {
            out.push_back(input[i]);
        }

        /* All the data is consumed so clear buffer */
        if(data.buf_len != 0) {
            memset(data.buf, 0x00, sizeof(data.buf));
            bufIndex = data.buf_len = 0;
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

}  // namespace javacard
}  // namespace V4_1
}  // namespace keymaster
