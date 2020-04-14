#pragma
#ifndef __CBOR_CONVERTER_H_
#define __CBOR_CONVERTER_H_
#include <sstream>
#include <iostream>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <numeric>
#include "cppbor.h"
#include "cppbor_parse.h"
using namespace cppbor;
/* Test Start */
typedef struct HmacSharingParameters {
    std::vector<uint8_t> seed;
    uint8_t nonce[32];
};
enum class HardwareAuthenticatorType {
    NONE = 0,
    PASSWORD = 1 << 0,
    FINGERPRINT = 1 << 1,
    ANY = 0xFFFFFFFF
};
typedef struct HardwareAuthToken {
    uint64_t challenge;
    uint64_t userId;
    uint64_t authenticatorId;
    HardwareAuthenticatorType authType;
    uint64_t timestamp;
    std::vector<uint8_t> mac;
};
enum class Algorithm {
    RSA = 0,
    ECDSA = 1,
    DSA = 2
};
enum class PaddingMode {
    PKCS_1 = 0,
    PKCS_5 = 1,
    OAEP = 2,
};
enum class TAG {
    ABC = 0,
    DEF = 1,
    GHI = 2
};
typedef struct KeyParameter {
    TAG tag;
    union IntegerParams {
        Algorithm algorithm;
        PaddingMode mode;
        bool boolValue;
        uint32_t u32t;
        uint64_t u64t;
    };
    IntegerParams f;
    std::vector<uint8_t> blob;
};
typedef struct VerificationToken {
    uint64_t challenge;
    uint64_t timestamp;

};
/*Test End*/
class CborConverter
{
public:
	CborConverter() = default;
	~CborConverter() = default;

	ParseResult decodeData(const std::vector<uint8_t> cborData);

    /* Use this function to get both signed and usinged integers.*/
	template<typename T>
    bool getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value);
    bool getHmacSharingParameters(const std::unique_ptr<Item>& item, const uint32_t pos, HmacSharingParameters& params);
    bool getBinaryArray(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<uint8_t>& vec);
    bool getHardwareAuthToken(const std::unique_ptr<Item>& item, const uint32_t pos, HardwareAuthToken& authType);
    bool getKeyParameters(const std::unique_ptr<Item>& item, const uint32_t pos, std::vector<KeyParameter> keyParams);
   

private:
	inline MajorType getType(const std::unique_ptr<Item> &item) { return item.get()->type(); }
    bool getKeyparameter(const std::pair<const std::unique_ptr<Item>&,
        const std::unique_ptr<Item>&> pair, KeyParameter& keyParam);
    inline const std::unique_ptr<Item>& getItemAtPos(const std::unique_ptr<Item>& item, const uint32_t pos) {
        const Array* arr = nullptr;

        if (MajorType::ARRAY != getType(item)) {
            return nullptr;
        }
        arr = item.get()->asArray();
        if (arr->size() < (pos + 1)) {
            return nullptr;
        }
        return (*arr)[pos];
    }
};

template<typename T>
bool CborConverter::getUint64(const std::unique_ptr<Item>& item, const uint32_t pos, T& value) {
    bool ret = false;
    const std::unique_ptr<Item>& intItem = getItemAtPos(item, pos);
    
    if ((intItem == nullptr) ||
        (std::is_unsigned<T>::value && (MajorType::UINT != getType(intItem))) ||
        ((std::is_signed<T>::value && (MajorType::NINT != getType(intItem))))) {
        return ret;
    }

    if (std::is_unsigned<T>::value) {
        const Uint* uintVal = intItem.get()->asUint();
        value = uintVal->value();
    }
    else {
        const Nint* nintVal = intItem.get()->asNint();
        value = nintVal->value();
    }
    ret = true;
    return ret; //success
}

#endif