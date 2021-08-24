/*
 * Copyright(C) 2020 The Android Open Source Project
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

package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
public class KMDecoder {

  // major types
  private static final short UINT_TYPE = 0x00;
  private static final short NEG_INT_TYPE = 0x20;
  private static final short BYTES_TYPE = 0x40;
  private static final short TSTR_TYPE = 0x60;
  private static final short ARRAY_TYPE = 0x80;
  private static final short MAP_TYPE = 0xA0;
  private static final short SIMPLE_VALUE_TYPE = 0xE0;

  // masks
  private static final short ADDITIONAL_MASK = 0x1F;
  private static final short MAJOR_TYPE_MASK = 0xE0;

  // value length
  private static final short UINT8_LENGTH = 0x18;
  private static final short UINT16_LENGTH = 0x19;
  private static final short UINT32_LENGTH = 0x1A;
  private static final short UINT64_LENGTH = 0x1B;

  private static final short SCRATCH_BUF_SIZE = 6;
  private static final short START_OFFSET = 0;
  private static final short LEN_OFFSET = 2;
  private static final short TAG_KEY_OFFSET = 4;
  private Object[] bufferRef;
  private short[] scratchBuf;

  public KMDecoder() {
    bufferRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    scratchBuf = JCSystem.makeTransientShortArray(SCRATCH_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
    bufferRef[0] = null;
    scratchBuf[START_OFFSET] = (short) 0;
    scratchBuf[LEN_OFFSET] = (short) 0;
    scratchBuf[TAG_KEY_OFFSET] = (short) 0;
  }

  public short decode(short expression, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length);
    return decode(expression);
  }

  public short decodeArray(short exp, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length);
    short payloadLength = readMajorTypeWithPayloadLength(ARRAY_TYPE);
    short expLength = KMArray.cast(exp).length();
    if (payloadLength > expLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short index = 0;
    short obj;
    short type;
    short arrPtr = KMArray.instance(payloadLength);
    while (index < payloadLength) {
      type = KMArray.cast(exp).get(index);
      obj = decode(type);
      KMArray.cast(arrPtr).add(index, obj);
      index++;
    }
    return arrPtr;
  }

  private short decode(short exp) {
    byte type = KMType.getType(exp);
    switch (type) {
      case KMType.BYTE_BLOB_TYPE:
        return decodeByteBlob(exp);
      case KMType.TEXT_STRING_TYPE:
        return decodeTstr(exp);
      case KMType.INTEGER_TYPE:
        return decodeInteger(exp);
      case KMType.SIMPLE_VALUE_TYPE:
        return decodeSimpleValue(exp);
      case KMType.NEG_INTEGER_TYPE:
        return decodeNegInteger(exp);
      case KMType.ARRAY_TYPE:
        return decodeArray(exp);
      case KMType.MAP_TYPE:
        return decodeMap(exp);
      case KMType.ENUM_TYPE:
        return decodeEnum(exp);
      case KMType.KEY_PARAM_TYPE:
        return decodeKeyParam(exp);
      case KMType.KEY_CHAR_TYPE:
        return decodeKeyChar(exp);
      case KMType.VERIFICATION_TOKEN_TYPE:
        return decodeVerificationToken(exp);
      case KMType.HMAC_SHARING_PARAM_TYPE:
        return decodeHmacSharingParam(exp);
      case KMType.HW_AUTH_TOKEN_TYPE:
        return decodeHwAuthToken(exp);
      case KMType.COSE_KEY_TYPE:
      case KMType.COSE_HEADERS_TYPE:
      case KMType.COSE_CERT_PAYLOAD_TYPE:
        return decodeCoseMap(exp);
      case KMType.COSE_PAIR_TAG_TYPE:
        short tagValueType = KMCosePairTagType.getTagValueType(exp);
        return decodeCosePairTag(tagValueType, exp);
      case KMType.TAG_TYPE:
        short tagType = KMTag.getTagType(exp);
        return decodeTag(tagType, exp);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  private short decodeTag(short tagType, short exp) {
    switch (tagType) {
      case KMType.BIGNUM_TAG:
        return decodeBignumTag(exp);
      case KMType.BYTES_TAG:
        return decodeBytesTag(exp);
      case KMType.BOOL_TAG:
        return decodeBoolTag(exp);
      case KMType.UINT_TAG:
      case KMType.ULONG_TAG:
      case KMType.DATE_TAG:
        return decodeIntegerTag(exp);
      case KMType.ULONG_ARRAY_TAG:
      case KMType.UINT_ARRAY_TAG:
        return decodeIntegerArrayTag(exp);
      case KMType.ENUM_TAG:
        return decodeEnumTag(exp);
      case KMType.ENUM_ARRAY_TAG:
        return decodeEnumArrayTag(exp);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  private short decodeVerificationToken(short exp) {
    short vals = decode(KMVerificationToken.cast(exp).getVals());
    return KMVerificationToken.instance(vals);
  }

  private short decodeHwAuthToken(short exp) {
    short vals = decode(KMHardwareAuthToken.cast(exp).getVals());
    return KMHardwareAuthToken.instance(vals);
  }

  private short decodeHmacSharingParam(short exp) {
    short vals = decode(KMHmacSharingParameters.cast(exp).getVals());
    return KMHmacSharingParameters.instance(vals);
  }

  private short decodeKeyChar(short exp) {
    short vals = decode(KMKeyCharacteristics.cast(exp).getVals());
    return KMKeyCharacteristics.instance(vals);
  }

  private short decodeCosePairKey(short exp) {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    short keyPtr = (short) 0;
    // Cose Key should be always either UINT or Negative int
    if ((buffer[startOff] & MAJOR_TYPE_MASK) == UINT_TYPE) {
      keyPtr = decodeInteger(exp);
    } else if ((buffer[startOff] & MAJOR_TYPE_MASK) == NEG_INT_TYPE) {
      keyPtr = decodeNegInteger(exp);
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    return keyPtr;
  }

  private short decodeCosePairSimpleValueTag(short exp) {
    short keyPtr = decodeCosePairKey((KMCosePairSimpleValueTag.cast(exp).getKeyPtr()));
    short valuePtr = decode(KMCosePairSimpleValueTag.cast(exp).getValuePtr());
    return KMCosePairSimpleValueTag.instance(keyPtr, valuePtr);
  }

  private short decodeCosePairIntegerValueTag(short exp) {
    short keyPtr = decodeCosePairKey((KMCosePairIntegerTag.cast(exp).getKeyPtr()));
    short valuePtr = decode(KMCosePairIntegerTag.cast(exp).getValuePtr());
    return KMCosePairIntegerTag.instance(keyPtr, valuePtr);
  }

  private short decodeCosePairNegIntegerTag(short exp) {
    short keyPtr = decodeCosePairKey((KMCosePairNegIntegerTag.cast(exp).getKeyPtr()));
    short valuePtr = decode(KMCosePairNegIntegerTag.cast(exp).getValuePtr());
    return KMCosePairNegIntegerTag.instance(keyPtr, valuePtr);
  }

  private short decodeCosePairTxtStringTag(short exp) {
    short keyPtr = decodeCosePairKey((KMCosePairTextStringTag.cast(exp).getKeyPtr()));
    short valuePtr = decode(KMCosePairTextStringTag.cast(exp).getValuePtr());
    return KMCosePairTextStringTag.instance(keyPtr, valuePtr);
  }

  private short decodeCosePairCoseKeyTag(short exp) {
    short keyPtr = decodeCosePairKey((KMCosePairCoseKeyTag.cast(exp).getKeyPtr()));
    short valuePtr = decode(KMCosePairCoseKeyTag.cast(exp).getValuePtr());
    return KMCosePairCoseKeyTag.instance(keyPtr, valuePtr);
  }

  private short decodeCosePairByteBlobTag(short exp) {
    short keyPtr = decodeCosePairKey((KMCosePairByteBlobTag.cast(exp).getKeyPtr()));
    short valuePtr = decode(KMCosePairByteBlobTag.cast(exp).getValuePtr());
    return KMCosePairByteBlobTag.instance(keyPtr, valuePtr);
  }

  private short peekCosePairTagType() {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    // Cose Key should be always either UINT or Negative int
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE &&
        (buffer[startOff] & MAJOR_TYPE_MASK) != NEG_INT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    short additionalMask = (short) (buffer[startOff] & ADDITIONAL_MASK);
    short increment = 0;
    if (additionalMask < UINT8_LENGTH) {
      increment++;
    } else if (additionalMask == UINT8_LENGTH) {
      increment += 2;
    } else if (additionalMask == UINT16_LENGTH) {
      increment += 3;
    } else if (additionalMask == UINT32_LENGTH) {
      increment += 5;
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short majorType = (short) (buffer[(short) (startOff + increment)] & MAJOR_TYPE_MASK);
    short tagValueType = 0;
    if (majorType == BYTES_TYPE) {
      tagValueType = KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE;
    } else if (majorType == UINT_TYPE) {
      tagValueType = KMType.COSE_PAIR_INT_TAG_TYPE;
    } else if (majorType == NEG_INT_TYPE) {
      tagValueType = KMType.COSE_PAIR_NEG_INT_TAG_TYPE;
    } else if (majorType == MAP_TYPE) {
      tagValueType = KMType.COSE_PAIR_COSE_KEY_TAG_TYPE;
    } else if (majorType == SIMPLE_VALUE_TYPE) {
      tagValueType = KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE;
    } else if (majorType == TSTR_TYPE) {
      tagValueType = KMType.COSE_PAIR_TEXT_STR_TAG_TYPE;
    }else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    return tagValueType;
  }

  private short decodeCosePairTag(short tagValueType, short exp) {
    switch (tagValueType) {
      case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
        return decodeCosePairByteBlobTag(exp);
      case KMType.COSE_PAIR_NEG_INT_TAG_TYPE:
        return decodeCosePairNegIntegerTag(exp);
      case KMType.COSE_PAIR_INT_TAG_TYPE:
        return decodeCosePairIntegerValueTag(exp);
      case KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE:
        return decodeCosePairSimpleValueTag(exp);
      case KMType.COSE_PAIR_COSE_KEY_TAG_TYPE:
        return decodeCosePairCoseKeyTag(exp);
      case KMType.COSE_PAIR_TEXT_STR_TAG_TYPE:
        return decodeCosePairTxtStringTag(exp);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  private short decodeCoseMap(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(MAP_TYPE);
    // get allowed key pairs
    short allowedKeyPairs = KMCoseMap.getVals(exp);
    short vals = KMArray.instance(payloadLength);
    short length = KMArray.cast(allowedKeyPairs).length();
    short index = 0;
    boolean tagFound;
    short tagInd;
    short cosePairTagType;
    short tagClass;
    short allowedType;
    short obj;

    // For each tag in payload ...
    while (index < payloadLength) {
      tagFound = false;
      tagInd = 0;
      cosePairTagType = peekCosePairTagType();
      // Check against the allowed tags ...
      while (tagInd < length) {
        tagClass = KMArray.cast(allowedKeyPairs).get(tagInd);
        allowedType = KMCosePairTagType.getTagValueType(tagClass);
        if (allowedType == cosePairTagType) {
          obj = decode(tagClass);
          KMArray.cast(vals).add(index, obj);
          tagFound = true;
          break;
        }
        tagInd++;
      }
      if (!tagFound) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      } else {
        index++;
      }
    }
    return KMCoseMap.createInstanceFromType(exp, vals);
  }

  private short decodeKeyParam(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(MAP_TYPE);
    // allowed tags
    short allowedTags = KMKeyParameters.cast(exp).getVals();
    short tagRule = KMArray.cast(allowedTags).get((short)0);
    boolean ignoreInvalidTags = KMEnum.cast(tagRule).getVal() == KMType.IGNORE_INVALID_TAGS;
    short vals = KMArray.instance(payloadLength);
    short length = KMArray.cast(allowedTags).length();
    short index = 0;
    boolean tagFound;
    short tagInd;
    short tagType;
    short tagClass;
    short allowedType;
    short obj;
    // For each tag in payload ...
    while (index < payloadLength) {
      tagFound = false;
      tagInd = 1;
      tagType = peekTagType();
      // Check against the allowed tags ...
      while (tagInd < length) {
        tagClass = KMArray.cast(allowedTags).get(tagInd);
        allowedType = KMTag.getTagType(tagClass);
        // If it is part of allowed tags ...
        if (tagType == allowedType) {
          // then decodeByteBlob and add that to the array.
          try {
            tagFound = true;
            obj = decode(tagClass);
            KMArray.cast(vals).add(index, obj);
            break;
          }catch(KMException e){
            if(KMException.reason() == KMError.INVALID_TAG &&
            !ignoreInvalidTags){
              KMException.throwIt(KMError.INVALID_TAG);
            }
          }
        }
        tagInd++;
      }
      if (!tagFound) {
        KMException.throwIt(KMError.INVALID_TAG);
      } else {
        index++;
      }
    }
    return KMKeyParameters.instance(vals);
  }

  private short decodeEnumArrayTag(short exp) {
    readTagKey(KMEnumArrayTag.cast(exp).getTagType());
    return KMEnumArrayTag.instance(scratchBuf[TAG_KEY_OFFSET], decode(KMEnumArrayTag.cast(exp).getValues()));
  }

  private short decodeIntegerArrayTag(short exp) {
    readTagKey(KMIntegerArrayTag.cast(exp).getTagType());
    // the values are array of integers.
    return KMIntegerArrayTag.instance(KMIntegerArrayTag.cast(exp).getTagType(),
        scratchBuf[TAG_KEY_OFFSET], decode(KMIntegerArrayTag.cast(exp).getValues()));
  }

  private short decodeIntegerTag(short exp) {
    readTagKey(KMIntegerTag.cast(exp).getTagType());
    // the value is an integer
    return KMIntegerTag.instance(KMIntegerTag.cast(exp).getTagType(),
        scratchBuf[TAG_KEY_OFFSET], decode(KMIntegerTag.cast(exp).getValue()));
  }

  private short decodeBytesTag(short exp) {
    readTagKey(KMByteTag.cast(exp).getTagType());
    // The value must be byte blob
    return KMByteTag.instance(scratchBuf[TAG_KEY_OFFSET], decode(KMByteTag.cast(exp).getValue()));
  }

  private short decodeBignumTag(short exp) {
    readTagKey(KMBignumTag.cast(exp).getTagType());
    // The value must be byte blob
    return KMBignumTag.instance(scratchBuf[TAG_KEY_OFFSET], decode(KMBignumTag.cast(exp).getValue()));
  }

  private short decodeMap(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(MAP_TYPE);
    short mapPtr = KMMap.instance(payloadLength);
    short index = 0;
    short type;
    short keyobj;
    short valueobj;
    while (index < payloadLength) {
      type = KMMap.cast(exp).getKey(index);
      keyobj = decode(type);
      type = KMMap.cast(exp).getKeyValue(index);
      valueobj = decode(type);
      KMMap.cast(mapPtr).add(index, keyobj, valueobj);
      index++;
    }
    return mapPtr;
  }

  private short decodeArray(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(ARRAY_TYPE);
    short arrPtr = KMArray.instance(payloadLength);
    short index = 0;
    short type;
    short obj;
    // check whether array contains one type of objects or multiple types
    if (KMArray.cast(exp).containedType() == 0) {// multiple types specified by expression.
      if (KMArray.cast(exp).length() != KMArray.ANY_ARRAY_LENGTH) {
        if (KMArray.cast(exp).length() != payloadLength) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
      }
      while (index < payloadLength) {
        type = KMArray.cast(exp).get(index);
        obj = decode(type);
        KMArray.cast(arrPtr).add(index, obj);
        index++;
      }
    } else { // Array is a Vector containing objects of one type
      type = KMArray.cast(exp).containedType();
      while (index < payloadLength) {
        obj = decode(type);
        KMArray.cast(arrPtr).add(index, obj);
        index++;
      }
    }
    return arrPtr;
  }

  private short decodeEnumTag(short exp) {
    readTagKey(KMEnumTag.cast(exp).getTagType());
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    // Enum Tag value will always be integer with max 1 byte length.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    byte enumVal = 0;
    if (len > UINT8_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (len < UINT8_LENGTH) {
      enumVal = (byte) (len & ADDITIONAL_MASK);
      incrementStartOff((short) 1);
    } else if (len == UINT8_LENGTH) {
      incrementStartOff((short) 1);
      // startOff  is incremented so update the startOff
      // with latest value before using it.
      startOff = scratchBuf[START_OFFSET];
      enumVal = buffer[startOff];
      incrementStartOff((short) 1);
    }
    return KMEnumTag.instance(scratchBuf[TAG_KEY_OFFSET], enumVal);
  }

  private short decodeBoolTag(short exp) {
    readTagKey(KMBoolTag.cast(exp).getTagType());
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    // BOOL Tag is a leaf node and it must always have tiny encoded uint value = 1.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if ((byte) (buffer[startOff] & ADDITIONAL_MASK) != 0x01) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    incrementStartOff((short) 1);
    return KMBoolTag.instance(scratchBuf[TAG_KEY_OFFSET]);
  }

  private short decodeEnum(short exp) {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    // Enum value will always be integer with max 1 byte length.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    byte enumVal;
    if (len > UINT8_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (len < UINT8_LENGTH) {
      enumVal = (byte) (len & ADDITIONAL_MASK);
      incrementStartOff((short) 1);
    } else {
      incrementStartOff((short) 1);
      // startOff  is incremented so update the startOff
      // with latest value before using it.
      startOff = scratchBuf[START_OFFSET];
      enumVal = buffer[startOff];
      incrementStartOff((short) 1);
    }
    return KMEnum.instance(KMEnum.cast(exp).getEnumType(), enumVal);
  }

  private short decodeSimpleValue(short exp) {
    short inst;
    short startOff = scratchBuf[START_OFFSET];
    byte[] buffer = (byte[]) bufferRef[0];
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != SIMPLE_VALUE_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    byte addInfo = (byte) (buffer[startOff] & ADDITIONAL_MASK);
    incrementStartOff((short) 1);
    return KMSimpleValue.instance(addInfo);
  }

  private short decodeInteger(short exp) {
    short inst;
    short startOff = scratchBuf[START_OFFSET];
    byte[] buffer = (byte[]) bufferRef[0];
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    if (len > UINT64_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    incrementStartOff((short) 1);
    // startOff  is incremented so update the startOff
    // with latest value before using it.
    startOff = scratchBuf[START_OFFSET];
    if (len < UINT8_LENGTH) {
      inst = KMInteger.uint_8((byte) (len & ADDITIONAL_MASK));
    } else if (len == UINT8_LENGTH) {
      inst = KMInteger.instance(buffer, startOff, (short) 1);
      incrementStartOff((short) 1);
    } else if (len == UINT16_LENGTH) {
      inst = KMInteger.instance(buffer, startOff, (short) 2);
      incrementStartOff((short) 2);
    } else if (len == UINT32_LENGTH) {
      inst = KMInteger.instance(buffer, startOff, (short) 4);
      incrementStartOff((short) 4);
    } else {
      inst = KMInteger.instance(buffer, startOff, (short) 8);
      incrementStartOff((short) 8);
    }
    return inst;
  }

  private short decodeNegIntegerValue(byte addInfo, byte[] buf, short startOffset) {
    short inst;
    short len = 0;
    short scratchpad;
    if (addInfo < UINT8_LENGTH) {
      addInfo = (byte) (-1 - addInfo);
      inst = KMNInteger.uint_8(addInfo);
    } else {
      switch (addInfo) {
        case UINT8_LENGTH:
          len = 1;
          break;
        case UINT16_LENGTH:
          len = 2;
          break;
        case UINT32_LENGTH:
          len = 4;
          break;
        case UINT64_LENGTH:
          len = 8;
          break;
        default:
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      // Do (-1 - N), as per cbor negative integer decoding rule.
      // N is the integer value.
      scratchpad = KMByteBlob.instance((short) (len * 3));
      byte[] input = KMByteBlob.cast(scratchpad).getBuffer();
      short offset = KMByteBlob.cast(scratchpad).getStartOff();
      Util.arrayFillNonAtomic(input, offset, len, (byte) -1);
      Util.arrayCopyNonAtomic(buf, startOffset, input, (short) (offset + len), len);
      KMUtils.subtract(input, offset, (short) (offset + len), (short) (offset + 2 * len), (byte) len);
      inst = KMNInteger.instance(input, (short) (offset + 2 * len), len);
      incrementStartOff(len);
    }
    return inst;
  }

  private short decodeNegInteger(short exp) {
    short startOff = scratchBuf[START_OFFSET];
    byte[] buffer = (byte[]) bufferRef[0];
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != NEG_INT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    if (len > UINT64_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    incrementStartOff((short) 1);
    // startOff  is incremented so update the startOff
    // with latest value before using it.
    startOff = scratchBuf[START_OFFSET];
    return decodeNegIntegerValue((byte) len, buffer, startOff);
  }

  private short decodeTstr(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(TSTR_TYPE);
    short inst = KMTextString.instance((byte[]) bufferRef[0], scratchBuf[START_OFFSET], payloadLength);
    incrementStartOff(payloadLength);
    return inst;
  }

  private short decodeByteBlob(short exp) {
    short payloadLength = readMajorTypeWithPayloadLength(BYTES_TYPE);
    short inst = KMByteBlob.instance((byte[]) bufferRef[0], scratchBuf[START_OFFSET], payloadLength);
    incrementStartOff(payloadLength);
    return inst;
  }

  private short peekTagType() {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    if ((short) (buffer[startOff] & ADDITIONAL_MASK) != UINT32_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return (short)
        ((Util.makeShort(buffer[(short) (startOff + 1)], buffer[(short) (startOff + 2)]))
            & KMType.TAG_TYPE_MASK);
  }

  private void readTagKey(short expectedTagType) {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if ((byte) (buffer[startOff] & ADDITIONAL_MASK) != UINT32_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    incrementStartOff((short) 1);
    short tagType = readShort();
    scratchBuf[TAG_KEY_OFFSET] = readShort();
    if (tagType != expectedTagType) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  // payload length cannot be more then 16 bits.
  private short readMajorTypeWithPayloadLength(short majorType) {
    short payloadLength;
    byte val = readByte();
    if ((short) (val & MAJOR_TYPE_MASK) != majorType) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short lenType = (short) (val & ADDITIONAL_MASK);
    if (lenType > UINT16_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (lenType < UINT8_LENGTH) {
      payloadLength = lenType;
    } else if (lenType == UINT8_LENGTH) {
      payloadLength = (short) (readByte() & 0xFF);
    } else {
      payloadLength = readShort();
    }
    return payloadLength;
  }

  private short readShort() {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    short val = Util.makeShort(buffer[startOff], buffer[(short) (startOff + 1)]);
    incrementStartOff((short) 2);
    return val;
  }

  private byte readByte() {
    short startOff = scratchBuf[START_OFFSET];
    byte val = ((byte[]) bufferRef[0])[startOff];
    incrementStartOff((short) 1);
    return val;
  }

  private void incrementStartOff(short inc) {
    scratchBuf[START_OFFSET] += inc;
    if (scratchBuf[START_OFFSET] > scratchBuf[LEN_OFFSET]) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public short readCertificateChainLengthAndHeaderLen(byte[] buf, short bufOffset,
                                                      short bufLen) {
    bufferRef[0] = buf;
    scratchBuf[START_OFFSET] = bufOffset;
    scratchBuf[LEN_OFFSET] = (short) (bufOffset + bufLen);
    short totalLen = readMajorTypeWithPayloadLength(BYTES_TYPE);
    totalLen += (short) (scratchBuf[START_OFFSET] - bufOffset);
    return totalLen;
  }
}
