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

public class KMEncoder {

  // major types
  private static final byte UINT_TYPE = 0x00;
  private static final byte NEG_INT_TYPE = 0x20;
  private static final byte BYTES_TYPE = 0x40;
  private static final byte TSTR_TYPE = 0x60;
  private static final byte ARRAY_TYPE = (byte) 0x80;
  private static final byte MAP_TYPE = (byte) 0xA0;
  private static final byte SIMPLE_VALUE_TYPE = (byte) 0xE0;

  // masks
  private static final byte ADDITIONAL_MASK = 0x1F;

  // value length
  private static final byte UINT8_LENGTH = (byte) 0x18;
  private static final byte UINT16_LENGTH = (byte) 0x19;
  private static final byte UINT32_LENGTH = (byte) 0x1A;
  private static final byte UINT64_LENGTH = (byte) 0x1B;
  private static final short TINY_PAYLOAD = 0x17;
  private static final short SHORT_PAYLOAD = 0x100;
  private static final short STACK_SIZE = (short) 50;
  private static final short SCRATCH_BUF_SIZE = (short) 6;
  private static final short START_OFFSET = (short) 0;
  private static final short LEN_OFFSET = (short) 2;
  private static final short STACK_PTR_OFFSET = (short) 4;

  private Object[] bufferRef;
  private short[] scratchBuf;
  private short[] stack;

  public KMEncoder() {
    bufferRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    scratchBuf = JCSystem.makeTransientShortArray(SCRATCH_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
    stack = JCSystem.makeTransientShortArray(STACK_SIZE, JCSystem.CLEAR_ON_RESET);
    bufferRef[0] = null;
    scratchBuf[START_OFFSET] = (short) 0;
    scratchBuf[LEN_OFFSET] = (short) 0;
    scratchBuf[STACK_PTR_OFFSET] = (short) 0;
  }

  private void push(short objPtr) {
    stack[scratchBuf[STACK_PTR_OFFSET]] = objPtr;
    scratchBuf[STACK_PTR_OFFSET]++;
  }

  private short pop() {
    scratchBuf[STACK_PTR_OFFSET]--;
    return stack[scratchBuf[STACK_PTR_OFFSET]];
  }

  private void encode(short obj) {
    push(obj);
  }

  public short encode(short object, byte[] buffer, short startOff) {
    scratchBuf[STACK_PTR_OFFSET] = 0;
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    short len = (short) (buffer.length - startOff);
    if ((len < 0) || len > KMKeymasterApplet.MAX_LENGTH) {
      scratchBuf[LEN_OFFSET] = KMKeymasterApplet.MAX_LENGTH;
    } else {
      scratchBuf[LEN_OFFSET] = (short) buffer.length;
    }
    //this.length = (short)(startOff + length);
    push(object);
    encode();
    return (short) (scratchBuf[START_OFFSET] - startOff);
  }

  // array{KMError.OK,Array{KMByteBlobs}}
  public void encodeCertChain(byte[] buffer, short offset, short length, short errInt32Ptr) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = offset;
    scratchBuf[LEN_OFFSET] = (short) (offset + 1);
    //Total length is ArrayHeader + [UIntHeader + length(errInt32Ptr)]
    scratchBuf[LEN_OFFSET] += (short) (1 + getEncodedIntegerLength(errInt32Ptr));

    writeMajorTypeWithLength(ARRAY_TYPE, (short) 2); // Array of 2 elements
    encodeUnsignedInteger(errInt32Ptr);
  }

  //array{KMError.OK,Array{KMByteBlobs}}
  public short encodeCert(byte[] certBuffer, short bufferStart, short certStart, short certLength, short errInt32Ptr) {
    bufferRef[0] = certBuffer;
    scratchBuf[START_OFFSET] = certStart;
    scratchBuf[LEN_OFFSET] = (short) (certStart + 1);
    //Array header - 2 elements i.e. 1 byte
    scratchBuf[START_OFFSET]--;
    // errInt32Ptr - PowerResetStatus + ErrorCode - 4 bytes
    // Integer header - 1 byte
    scratchBuf[START_OFFSET] -= getEncodedIntegerLength(errInt32Ptr);
    //Array header - 2 elements i.e. 1 byte
    scratchBuf[START_OFFSET]--;
    // Cert Byte blob - typically 2 bytes length i.e. 3 bytes header
    scratchBuf[START_OFFSET] -= 2;
    if (certLength >= SHORT_PAYLOAD) {
      scratchBuf[START_OFFSET]--;
    }
    if (scratchBuf[START_OFFSET] < bufferStart) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    bufferStart = scratchBuf[START_OFFSET];
    writeMajorTypeWithLength(ARRAY_TYPE, (short) 2); // Array of 2 elements
    encodeUnsignedInteger(errInt32Ptr); //PowerResetStatus + ErrorCode
    writeMajorTypeWithLength(ARRAY_TYPE, (short) 1); // Array of 1 element
    writeMajorTypeWithLength(BYTES_TYPE, certLength); // Cert Byte Blob of length
    return bufferStart;
  }

  public short encodeError(short errInt32Ptr, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length + 1);
    encodeUnsignedInteger(errInt32Ptr);
    return (short) (scratchBuf[START_OFFSET] - startOff);
  }

  private void encode() {
    while (scratchBuf[STACK_PTR_OFFSET] > 0) {
      short exp = pop();
      byte type = KMType.getType(exp);
      switch (type) {
        case KMType.BYTE_BLOB_TYPE:
          encodeByteBlob(exp);
          break;
        case KMType.TEXT_STRING_TYPE:
          encodeTextString(exp);
          break;
        case KMType.INTEGER_TYPE:
          encodeUnsignedInteger(exp);
          break;
        case KMType.SIMPLE_VALUE_TYPE:
          encodeSimpleValue(exp);
          break;
        case KMType.NEG_INTEGER_TYPE:
          encodeNegInteger(exp);
          break;
        case KMType.ARRAY_TYPE:
          encodeArray(exp);
          break;
        case KMType.MAP_TYPE:
          encodeMap(exp);
          break;
        case KMType.ENUM_TYPE:
          encodeEnum(exp);
          break;
        case KMType.KEY_PARAM_TYPE:
          encodeKeyParam(exp);
          break;
        case KMType.COSE_KEY_TYPE:
        case KMType.COSE_HEADERS_TYPE:
        case KMType.COSE_CERT_PAYLOAD_TYPE:
          encodeCoseMap(exp);
          break;
        case KMType.KEY_CHAR_TYPE:
          encodeKeyChar(exp);
          break;
        case KMType.VERIFICATION_TOKEN_TYPE:
          encodeVeriToken(exp);
          break;
        case KMType.HMAC_SHARING_PARAM_TYPE:
          encodeHmacSharingParam(exp);
          break;
        case KMType.HW_AUTH_TOKEN_TYPE:
          encodeHwAuthToken(exp);
          break;
        case KMType.TAG_TYPE:
          short tagType = KMTag.getTagType(exp);
          encodeTag(tagType, exp);
          break;
        case KMType.COSE_PAIR_TAG_TYPE:
          short cosePairTagType = KMCosePairTagType.getTagValueType(exp);
          encodeCosePairTag(cosePairTagType, exp);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
    }
  }

  private void encodeCosePairIntegerTag(short exp) {
    KMCosePairIntegerTag cosePairIntTag = KMCosePairIntegerTag.cast(exp);
    // push key and value ptr in stack to get encoded.
    encode(cosePairIntTag.getValuePtr());
    encode(cosePairIntTag.getKeyPtr());
  }

  private void encodeCosePairByteBlobTag(short exp) {
    KMCosePairByteBlobTag cosePairByteBlobTag = KMCosePairByteBlobTag.cast(exp);
    // push key and value ptr in stack to get encoded.
    encode(cosePairByteBlobTag.getValuePtr());
    encode(cosePairByteBlobTag.getKeyPtr());
  }

  private void encodeCosePairCoseKeyTag(short exp) {
    KMCosePairCoseKeyTag cosePairCoseKeyTag = KMCosePairCoseKeyTag.cast(exp);
    // push key and value ptr in stack to get encoded.
    encode(cosePairCoseKeyTag.getValuePtr());
    encode(cosePairCoseKeyTag.getKeyPtr());
  }

  private void encodeCosePairTextStringTag(short exp) {
    KMCosePairTextStringTag cosePairTextStringTag = KMCosePairTextStringTag.cast(exp);
    // push key and value ptr in stack to get encoded.
    encode(cosePairTextStringTag.getValuePtr());
    encode(cosePairTextStringTag.getKeyPtr());
  }

  private void encodeCosePairSimpleValueTag(short exp) {
    KMCosePairSimpleValueTag cosePairSimpleValueTag = KMCosePairSimpleValueTag.cast(exp);
    // push key and value ptr in stack to get encoded.
    encode(cosePairSimpleValueTag.getValuePtr());
    encode(cosePairSimpleValueTag.getKeyPtr());
  }

  private void encodeCosePairNegIntegerTag(short exp) {
    KMCosePairNegIntegerTag cosePairNegIntegerTag = KMCosePairNegIntegerTag.cast(exp);
    // push key and value ptr in stack to get encoded.
    encode(cosePairNegIntegerTag.getValuePtr());
    encode(cosePairNegIntegerTag.getKeyPtr());
  }

  private void encodeCosePairTag(short tagType, short exp) {
    switch (tagType) {
      case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
        encodeCosePairByteBlobTag(exp);
        return;
      case KMType.COSE_PAIR_INT_TAG_TYPE:
        encodeCosePairIntegerTag(exp);
        return;
      case KMType.COSE_PAIR_NEG_INT_TAG_TYPE:
        encodeCosePairNegIntegerTag(exp);
        return;
      case KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE:
        encodeCosePairSimpleValueTag(exp);
        return;
      case KMType.COSE_PAIR_TEXT_STR_TAG_TYPE:
        encodeCosePairTextStringTag(exp);
        return;
      case KMType.COSE_PAIR_COSE_KEY_TAG_TYPE:
        encodeCosePairCoseKeyTag(exp);
        return;
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  private void encodeTag(short tagType, short exp) {
    switch (tagType) {
      case KMType.BYTES_TAG:
        encodeBytesTag(exp);
        return;
      case KMType.BOOL_TAG:
        encodeBoolTag(exp);
        return;
      case KMType.UINT_TAG:
      case KMType.ULONG_TAG:
      case KMType.DATE_TAG:
        encodeIntegerTag(exp);
        return;
      case KMType.ULONG_ARRAY_TAG:
      case KMType.UINT_ARRAY_TAG:
        encodeIntegerArrayTag(exp);
        return;
      case KMType.ENUM_TAG:
        encodeEnumTag(exp);
        return;
      case KMType.ENUM_ARRAY_TAG:
        encodeEnumArrayTag(exp);
        return;
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  private void encodeCoseMap(short obj) {
    encodeAsMap(KMCoseMap.getVals(obj));
  }

  private void encodeKeyParam(short obj) {
    encodeAsMap(KMKeyParameters.cast(obj).getVals());
  }

  private void encodeKeyChar(short obj) {
    encode(KMKeyCharacteristics.cast(obj).getVals());
  }

  private void encodeVeriToken(short obj) {
    encode(KMVerificationToken.cast(obj).getVals());
  }

  private void encodeHwAuthToken(short obj) {
    encode(KMHardwareAuthToken.cast(obj).getVals());
  }

  private void encodeHmacSharingParam(short obj) {
    encode(KMHmacSharingParameters.cast(obj).getVals());
  }

  private void encodeArray(short obj) {
    writeMajorTypeWithLength(ARRAY_TYPE, KMArray.cast(obj).length());
    short len = KMArray.cast(obj).length();
    short index = (short) (len - 1);
    short subObj;
    while (index >= 0) {
      subObj = KMArray.cast(obj).get(index);
      if (subObj != KMType.INVALID_VALUE)
        encode(subObj);
      index--;
    }
  }

public void encodeArrayOnlyLength(short arrLength, byte[] buffer, short offset, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = offset;
    scratchBuf[LEN_OFFSET] = (short) (offset + length + 1);
    writeMajorTypeWithLength(ARRAY_TYPE, length);
  }

  private void encodeMap(short obj) {
    writeMajorTypeWithLength(MAP_TYPE, KMMap.cast(obj).length());
    short len = KMMap.cast(obj).length();
    short index = (short) (len - 1);
    while (index >= 0) {
      encode(KMMap.cast(obj).getKeyValue(index));
      encode(KMMap.cast(obj).getKey(index));
      index--;
    }
  }

  private void encodeAsMap(short obj) {
    writeMajorTypeWithLength(MAP_TYPE, KMArray.cast(obj).length());
    short len = KMArray.cast(obj).length();
    short index = (short) (len - 1);
    short inst;
    while (index >= 0) {
      inst = KMArray.cast(obj).get(index);
      encode(inst);
      index--;
    }
  }

  private void encodeIntegerArrayTag(short obj) {
    writeTag(KMIntegerArrayTag.cast(obj).getTagType(), KMIntegerArrayTag.cast(obj).getKey());
    encode(KMIntegerArrayTag.cast(obj).getValues());
  }

  private void encodeEnumArrayTag(short obj) {
    writeTag(KMEnumArrayTag.cast(obj).getTagType(), KMEnumArrayTag.cast(obj).getKey());
    encode(KMEnumArrayTag.cast(obj).getValues());
  }

  private void encodeIntegerTag(short obj) {
    writeTag(KMIntegerTag.cast(obj).getTagType(), KMIntegerTag.cast(obj).getKey());
    encode(KMIntegerTag.cast(obj).getValue());
  }

  private void encodeBytesTag(short obj) {
    writeTag(KMByteTag.cast(obj).getTagType(), KMByteTag.cast(obj).getKey());
    encode(KMByteTag.cast(obj).getValue());
  }

  private void encodeBoolTag(short obj) {
    writeTag(KMBoolTag.cast(obj).getTagType(), KMBoolTag.cast(obj).getKey());
    writeByteValue(KMBoolTag.cast(obj).getVal());
  }

  private void encodeEnumTag(short obj) {
    writeTag(KMEnumTag.cast(obj).getTagType(), KMEnumTag.cast(obj).getKey());
    writeByteValue(KMEnumTag.cast(obj).getValue());
  }

  private void encodeEnum(short obj) {
    writeByteValue(KMEnum.cast(obj).getVal());
  }

  private void encodeInteger(byte[] val, short len, short startOff, short majorType) {
    // find out the most significant byte
    short msbIndex = findMsb(val, startOff, len);
    // find the difference between most significant byte and len
    short diff = (short) (len - msbIndex);
    if (diff == 0) {
      writeByte((byte) (majorType | 0));
    } else if ((diff == 1) && (val[(short) (startOff + msbIndex)] < UINT8_LENGTH)
        && (val[(short) (startOff + msbIndex)] >= 0)) {
      writeByte((byte) (majorType | val[(short) (startOff + msbIndex)]));
    } else if (diff == 1) {
      writeByte((byte) (majorType | UINT8_LENGTH));
      writeByte(val[(short) (startOff + msbIndex)]);
    } else if (diff == 2) {
      writeByte((byte) (majorType | UINT16_LENGTH));
      writeBytes(val, (short) (startOff + msbIndex), (short) 2);
    } else if (diff <= 4) {
      writeByte((byte) (majorType | UINT32_LENGTH));
      writeBytes(val, (short) (startOff + len - 4), (short) 4);
    } else {
      writeByte((byte) (majorType | UINT64_LENGTH));
      writeBytes(val, startOff, (short) 8);
    }
  }

  // find out the most significant byte
  public short findMsb(byte[] buf, short offset, short len) {
    byte index = 0;
    // find out the most significant byte
    while (index < len) {
      if (buf[(short) (offset + index)] > 0) {
        break;
      } else if (buf[(short) (offset + index)] < 0) {
        break;
      }
      index++; // index will be equal to len if value is 0.
    }
    return index;
  }

  public void computeOnesCompliment(short msbIndex, byte[] buf, short offset, short len) {
    // find the difference between most significant byte and len
    short diff = (short) (len - msbIndex);
    short correctedOffset = offset;
    short correctedLen = len;
    // The offset and length of the buffer for Short and Byte types should be
    // corrected before computing the 1s compliment. The reason for doing this
    // is to avoid computation of 1s compliment on the MSB bytes.
    if (diff == 0) {
      // Fail
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    } else if (diff == 1) {
      correctedOffset = (short) (offset + 3);
      correctedLen = 1;
    } else if (diff == 2) {
      correctedOffset = (short) (offset + 2);
      correctedLen = 2;
    }
    // For int and long values the len and offset values are always proper.
    // int - 4 bytes
    // long - 8 bytes.
    KMUtils.computeOnesCompliment(buf, correctedOffset, correctedLen);
  }

  // Encoding rule for negative Integers is taken from
  // https://datatracker.ietf.org/doc/html/rfc7049#section-2.1, Major type 1.
  public short handleNegIntegerEncodingRule(byte[] buf, short offset, short len) {
    short msbIndex = findMsb(buf, offset, len);
    // Do -1-N, where N is the negative integer
    // The value of -1-N is equal to the 1s compliment of N.
    computeOnesCompliment(msbIndex, buf, offset, len);
    return msbIndex;
  }

  // Note: This function modifies the buffer's actual value. So after encoding, restore the original
  // value by calling removeNegIntegerEncodingRule().
  public short applyNegIntegerEncodingRule(byte[] buf, short offset, short len) {
    return handleNegIntegerEncodingRule(buf, offset, len);
  }

  public void removeNegIntegerEncodingRule(byte[] buf, short offset, short len, short origMsbIndex) {
    // Do -1-N, where N is the negative integer
    // The value of -1-N is equal to the 1s compliment of N.
    computeOnesCompliment(origMsbIndex, buf, offset, len);
  }

  private void encodeNegInteger(short obj) {
    byte[] val = KMNInteger.cast(obj).getBuffer();
    short len = KMNInteger.cast(obj).length();
    short startOff = KMNInteger.cast(obj).getStartOff();
    short msbIndex = applyNegIntegerEncodingRule(val, startOff, len);
    encodeInteger(val, len, startOff, NEG_INT_TYPE);
    removeNegIntegerEncodingRule(val, startOff, len, msbIndex);
  }

  private void encodeUnsignedInteger(short obj) {
    byte[] val = KMInteger.cast(obj).getBuffer();
    short len = KMInteger.cast(obj).length();
    short startOff = KMInteger.cast(obj).getStartOff();
    encodeInteger(val, len, startOff, UINT_TYPE);
  }

  private void encodeSimpleValue(short obj) {
    byte value = KMSimpleValue.cast(obj).getValue();
    writeByte((byte) (SIMPLE_VALUE_TYPE | value));
  }

  private void encodeTextString(short obj) {
    writeMajorTypeWithLength(TSTR_TYPE, KMTextString.cast(obj).length());
    writeBytes(KMTextString.cast(obj).getBuffer(), KMTextString.cast(obj).getStartOff(),
        KMTextString.cast(obj).length());
  }

  public short encodeByteBlobHeader(short bufLen, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length + 1);
    writeMajorTypeWithLength(BYTES_TYPE, bufLen);
    return (short) (scratchBuf[START_OFFSET] - startOff);
  }

  private void encodeByteBlob(short obj) {
    writeMajorTypeWithLength(BYTES_TYPE, KMByteBlob.cast(obj).length());
    writeBytes(KMByteBlob.cast(obj).getBuffer(), KMByteBlob.cast(obj).getStartOff(),
        KMByteBlob.cast(obj).length());
  }

  public short getEncodedLength(short ptr) {
    short len = 0;
    short type = KMType.getType(ptr);
    switch (type) {
      case KMType.BYTE_BLOB_TYPE:
        len += getEncodedByteBlobLength(ptr);
        break;
      case KMType.TEXT_STRING_TYPE:
        len += getEncodedTextStringLength(ptr);
        break;
      case KMType.INTEGER_TYPE:
        len += getEncodedIntegerLength(ptr);
        break;
      case KMType.NEG_INTEGER_TYPE:
        len += getEncodedNegIntegerLength(ptr);
        break;
      case KMType.ARRAY_TYPE:
        len += getEncodedArrayLen(ptr);
        break;
      case KMType.MAP_TYPE:
        len += getEncodedMapLen(ptr);
        break;
      case KMType.COSE_PAIR_TAG_TYPE:
        short cosePairTagType = KMCosePairTagType.getTagValueType(ptr);
        len += getEncodedCosePairTagLen(cosePairTagType, ptr);
        break;
      case KMType.COSE_KEY_TYPE:
      case KMType.COSE_HEADERS_TYPE:
      case KMType.COSE_CERT_PAYLOAD_TYPE:
        len += getEncodedArrayLen(KMCoseMap.getVals(ptr));
        break;
      default:
        KMException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return len;
  }

  private short getEncodedCosePairTagLen(short tagType, short exp) {
    short length = 0;
    switch (tagType) {
      case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
        KMCosePairByteBlobTag cosePairByteBlobTag = KMCosePairByteBlobTag.cast(exp);
        length = getEncodedLength(cosePairByteBlobTag.getKeyPtr());
        length += getEncodedLength(cosePairByteBlobTag.getValuePtr());
        break;
      case KMType.COSE_PAIR_INT_TAG_TYPE:
        KMCosePairIntegerTag cosePairIntTag = KMCosePairIntegerTag.cast(exp);
        length = getEncodedLength(cosePairIntTag.getValuePtr());
        length += getEncodedLength(cosePairIntTag.getKeyPtr());
        break;
      case KMType.COSE_PAIR_NEG_INT_TAG_TYPE:
        KMCosePairNegIntegerTag cosePairNegIntegerTag = KMCosePairNegIntegerTag.cast(exp);
        length = getEncodedLength(cosePairNegIntegerTag.getValuePtr());
        length += getEncodedLength(cosePairNegIntegerTag.getKeyPtr());
        break;
      case KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE:
        KMCosePairSimpleValueTag cosePairSimpleValueTag = KMCosePairSimpleValueTag.cast(exp);
        length = getEncodedLength(cosePairSimpleValueTag.getValuePtr());
        length += getEncodedLength(cosePairSimpleValueTag.getKeyPtr());
        break;
      case KMType.COSE_PAIR_TEXT_STR_TAG_TYPE:
        KMCosePairTextStringTag cosePairTextStringTag = KMCosePairTextStringTag.cast(exp);
        length = getEncodedLength(cosePairTextStringTag.getValuePtr());
        length += getEncodedLength(cosePairTextStringTag.getKeyPtr());
        break;
      case KMType.COSE_PAIR_COSE_KEY_TAG_TYPE:
        KMCosePairCoseKeyTag cosePairCoseKeyTag = KMCosePairCoseKeyTag.cast(exp);
        length = getEncodedLength(cosePairCoseKeyTag.getValuePtr());
        length += getEncodedLength(cosePairCoseKeyTag.getKeyPtr());
        break;
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    return length;
  }

  private short getEncodedMapLen(short obj) {
    short mapLen = KMMap.cast(obj).length();
    short len = getEncodedBytesLength(mapLen);
    short index = 0;
    while (index < mapLen) {
      len += getEncodedLength(KMMap.cast(obj).getKey(index));
      len += getEncodedLength(KMMap.cast(obj).getKeyValue(index));
      index++;
    }
    return len;
  }

  private short getEncodedArrayLen(short obj) {
    short arrLen = KMArray.cast(obj).length();
    short len = getEncodedBytesLength(arrLen);
    short index = 0;
    short subObj;
    while (index < arrLen) {
      subObj = KMArray.cast(obj).get(index);
      if (subObj != KMType.INVALID_VALUE)
        len += getEncodedLength(subObj);
      index++;
    }
    return len;
  }

  private short getEncodedBytesLength(short len) {
    short ret = 0;
    if (len < KMEncoder.UINT8_LENGTH && len >= 0) {
      ret = 1;
    } else if (len >= KMEncoder.UINT8_LENGTH && len <= (short) 0x00FF) {
      ret = 2;
    } else if (len > (short) 0x00FF && len <= (short) 0x7FFF) {
      ret = 3;
    } else {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return ret;
  }

  private short getEncodedByteBlobLength(short obj) {
    short len = KMByteBlob.cast(obj).length();
    len += getEncodedBytesLength(len);
    return len;
  }

  private short getEncodedTextStringLength(short obj) {
    short len = KMTextString.cast(obj).length();
    len += getEncodedBytesLength(len);
    return len;
  }

  private short getEncodedNegIntegerLength(short obj) {
    byte[] buf = KMNInteger.cast(obj).getBuffer();
    short len = KMNInteger.cast(obj).length();
    short offset = KMNInteger.cast(obj).getStartOff();
    short msbIndex = applyNegIntegerEncodingRule(buf, offset, len);
    short ret = getEncodedIntegerLength(buf, offset, len);
    removeNegIntegerEncodingRule(buf, offset, len, msbIndex);
    return ret;
  }

  private short getEncodedIntegerLength(byte[] val, short startOff, short len) {
    short msbIndex = findMsb(val, startOff, len);
    // find the difference between most significant byte and len
    short diff = (short) (len - msbIndex);
    switch (diff) {
      case 0: case 1: //Byte
        if ((val[(short) (startOff + msbIndex)] < KMEncoder.UINT8_LENGTH) &&
            (val[(short) (startOff + msbIndex)] >= 0)) {
          return (short) 1;
        } else {
          return (short) 2;
        }
      case 2: //Short
        return (short) 3;
      case 3: case 4: //UInt32
        return (short) 5;
      case 5: case 6: case 7: case 8: //UInt64
        return (short) 9;
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    return 0;
  }

  private short getEncodedIntegerLength(short obj) {
    byte[] val = KMInteger.cast(obj).getBuffer();
    short len = KMInteger.cast(obj).length();
    short startOff = KMInteger.cast(obj).getStartOff();
    return getEncodedIntegerLength(val, startOff, len);
  }

  private void writeByteValue(byte val) {
    if ((val < UINT8_LENGTH) && (val >= 0)) {
      writeByte((byte) (UINT_TYPE | val));
    } else {
      writeByte((byte) (UINT_TYPE | UINT8_LENGTH));
      writeByte(val);
    }
  }

  private void writeTag(short tagType, short tagKey) {
    writeByte((byte) (UINT_TYPE | UINT32_LENGTH));
    writeShort(tagType);
    writeShort(tagKey);
  }

  private void writeMajorTypeWithLength(byte majorType, short len) {
    if (len <= TINY_PAYLOAD) {
      writeByte((byte) (majorType | (byte) (len & ADDITIONAL_MASK)));
    } else if (len < SHORT_PAYLOAD) {
      writeByte((byte) (majorType | UINT8_LENGTH));
      writeByte((byte) (len & 0xFF));
    } else {
      writeByte((byte) (majorType | UINT16_LENGTH));
      writeShort(len);
    }
  }

  private void writeBytes(byte[] buf, short start, short len) {
    byte[] buffer = (byte[]) bufferRef[0];
    Util.arrayCopyNonAtomic(buf, start, buffer, scratchBuf[START_OFFSET], len);
    incrementStartOff(len);
  }

  private void writeShort(short val) {
    byte[] buffer = (byte[]) bufferRef[0];
    buffer[scratchBuf[START_OFFSET]] = (byte) ((val >> 8) & 0xFF);
    incrementStartOff((short) 1);
    buffer[scratchBuf[START_OFFSET]] = (byte) ((val & 0xFF));
    incrementStartOff((short) 1);
  }

  private void writeByte(byte val) {
    byte[] buffer = (byte[]) bufferRef[0];
    buffer[scratchBuf[START_OFFSET]] = val;
    incrementStartOff((short) 1);
  }

  private void incrementStartOff(short inc) {
    scratchBuf[START_OFFSET] += inc;
    if (scratchBuf[START_OFFSET] >= scratchBuf[LEN_OFFSET]) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }
}
