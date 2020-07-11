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
#define AES_BLOCK_SIZE          16
#define DES_BLOCK_SIZE           8
#define RSA_INPUT_MSG_LEN      245 /*(256-11)*/
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
            default:
                continue;
        }
	}
    return ErrorCode::OK;
}

ErrorCode OperationContext::setOperationInfo(uint64_t operationHandle, KeyPurpose purpose, const hidl_vec<KeyParameter>& params) {
    ErrorCode errorCode = ErrorCode::OK;
    OperationInfo info;
    if(ErrorCode::OK != (errorCode = hidlParamSet2OperatinInfo(params, info))) {
        return errorCode;
    }
    info.purpose = purpose;
    return setOperationInfo(operationHandle, info);
}

ErrorCode OperationContext::setOperationInfo(uint64_t operationHandle, OperationInfo& operInfo) {
    OperationData data;
    data.info = operInfo;
    memset((void*)&(data.data), 0x00, sizeof(data.data));
    operationTable[operationHandle] = data;
    return ErrorCode::OK;
}

ErrorCode OperationContext::getOperationInfo(uint64_t operHandle, OperationInfo& operInfo) {
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

ErrorCode OperationContext::validateInputData(uint64_t operHandle, Operation opr, const std::vector<uint8_t>& actualInput, std::vector<uint8_t>& input) {
    ErrorCode errorCode = ErrorCode::OK;
    OperationData oprData;

    if(ErrorCode::OK != (errorCode = getOperationData(operHandle, oprData))) {
        return errorCode;
    }

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

        if(oprData.info.pad == PaddingMode::NONE && oprData.info.alg == Algorithm::AES) {
            if(((oprData.data.buf_len+actualInput.size()) % AES_BLOCK_SIZE) != 0)
                return ErrorCode::INVALID_INPUT_LENGTH;
        }
        if(oprData.info.pad == PaddingMode::NONE && oprData.info.alg == Algorithm::TRIPLE_DES) {
            if(((oprData.data.buf_len+actualInput.size()) % DES_BLOCK_SIZE) != 0)
                return ErrorCode::INVALID_INPUT_LENGTH;
        }
    }
    input = actualInput;
    return errorCode;
}

ErrorCode OperationContext::update(uint64_t operHandle, const std::vector<uint8_t>& actualInput, sendDataToSE_cb cb) {
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

    /* Send if any buffered data is remaining or to call finish */
    if(ErrorCode::OK != (errorCode = handleInternalUpdate(operHandle, nullptr, 0,
                    Operation::Finish, cb, true))) {
        return errorCode;
    }
    return errorCode;
}

ErrorCode OperationContext::internalUpdate(uint64_t operHandle, uint8_t* input, size_t input_len, Operation opr, std::vector<uint8_t>& out) {
    int dataToSELen=0;
    /*Length of the data consumed from input */
    int inputConsumed=0;
    bool dataSendToSE = true;
    int blockSize = 0;
    BufferedData& data = operationTable[operHandle].data;
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
