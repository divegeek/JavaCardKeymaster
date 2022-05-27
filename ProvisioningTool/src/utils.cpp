/*
 **
 ** Copyright 2021, The Android Open Source Project
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
#include <iomanip>
#include <utils.h>
#include <fstream>
#include <constants.h>


constexpr char hex_value[256] = {0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 1,  2,  3,  4,  5,  6,  7, 8, 9, 0, 0, 0, 0, 0, 0,  // '0'..'9'
                                 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'A'..'F'
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'a'..'f'
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0};

std::string getHexString(std::vector<uint8_t>& input) { 
   std::stringstream ss;
   for (auto b : input) {
       ss << std::setw(2) << std::setfill('0') << std::hex << (int) (b & 0xFF);
   }
   return ss.str();
}


std::string hex2str(std::string a) { 
    std::string b;
    size_t num = a.size() / 2;
    b.resize(num);
    for (size_t i = 0; i < num; i++) {
        b[i] = (hex_value[a[i * 2] & 0xFF] << 4) + (hex_value[a[i * 2 + 1] & 0xFF]);
    }    
    return b;
}


// Parses the json file and returns 0 if success; otherwise 1.
int readJsonFile(Json::Value& root, std::string& inputFileName) {
    Json::CharReaderBuilder builder;
    std::string errorMessage;

    if(!root.empty()) {
        // Already parsed.
        return 0;
    }
    std::ifstream stream(inputFileName);
    if (Json::parseFromStream(builder, stream, &root, &errorMessage)) {
        printf("\n Parsed json file successfully.\n");
        return 0;
    } else {
        printf("\n Failed to parse json file  error:%s\n", errorMessage.c_str());
        return 1;
    }
}

// Write the json data to the output file.
int writeJsonFile(Json::Value& writerRoot, std::string& outputFileName) {
    
    std::ofstream ofs;
    // Delete file if already exists.
    std::remove(outputFileName.data());
    ofs.open(outputFileName, std::ofstream::out | std::ios_base::app);
    if (ofs.fail()) {
        printf("\n Fail to open the output file:%s", outputFileName.c_str());
        return FAILURE;
    }

    Json::StyledWriter styledWriter;
    ofs << styledWriter.write(writerRoot);

    ofs.close();
    return SUCCESS;
}
