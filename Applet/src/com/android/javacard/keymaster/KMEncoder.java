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
  private static final byte BYTES_TYPE = 0x40;
  private static final byte ARRAY_TYPE = (byte) 0x80;
  private static final byte MAP_TYPE = (byte) 0xA0;

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
    scratchBuf = JCSystem.makeTransientShortArray((short) SCRATCH_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
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
    short len = (short) buffer.length;
    if ((len < 0) || (len > KMKeymasterApplet.MAX_LENGTH)) {
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
    encodeInteger(errInt32Ptr);
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
    encodeInteger(errInt32Ptr); //PowerResetStatus + ErrorCode
    writeMajorTypeWithLength(ARRAY_TYPE, (short) 1); // Array of 1 element
    writeMajorTypeWithLength(BYTES_TYPE, certLength); // Cert Byte Blob of length
    return bufferStart;
  }

  public short encodeError(short errInt32Ptr, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length + 1);
    encodeInteger(errInt32Ptr);
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
        case KMType.INTEGER_TYPE:
          encodeInteger(exp);
          break;
        case KMType.ARRAY_TYPE:
          encodeArray(exp);
          break;
        case KMType.ENUM_TYPE:
          encodeEnum(exp);
          break;
        case KMType.KEY_PARAM_TYPE:
          encodeKeyParam(exp);
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
        default:
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
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
    while (index >= 0) {
      encode(KMArray.cast(obj).get(index));
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

  /* The total length of UINT Major type along with actual length of
   * integer is returned.
   */
  public short getEncodedIntegerLength(short obj) {
    byte[] val = KMInteger.cast(obj).getBuffer();
    short len = KMInteger.cast(obj).length();
    short startOff = KMInteger.cast(obj).getStartOff();
    byte index = 0;
    // find out the most significant byte
    while (index < len) {
      if (val[(short) (startOff + index)] > 0) {
        break;
      } else if (val[(short) (startOff + index)] < 0) {
        break;
      }
      index++; // index will be equal to len if value is 0.
    }
    // find the difference between most significant byte and len
    short diff = (short) (len - index);
    switch (diff) {
    case 0: case 1: //Byte | Short
      if ((val[(short) (startOff + index)] < UINT8_LENGTH) &&
          (val[(short) (startOff + index)] >= 0)) {
        return (short) 1;
      } else {
        return (short) 2;
      }
    case 2: //Short
      return (short) 3;
    case 3: case 4: //Uint32
      return (short) 5;
    case 5: case 6: case 7: case 8: //Uint64
      return (short) 9;
    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    return 0;
  }
  
  private void encodeInteger(short obj) {
    byte[] val = KMInteger.cast(obj).getBuffer();
    short len = KMInteger.cast(obj).length();
    short startOff = KMInteger.cast(obj).getStartOff();
    byte index = 0;
    // find out the most significant byte
    while (index < len) {
      if (val[(short) (startOff + index)] > 0) {
        break;
      } else if (val[(short) (startOff + index)] < 0) {
        break;
      }
      index++; // index will be equal to len if value is 0.
    }
    // find the difference between most significant byte and len
    short diff = (short) (len - index);
    if (diff == 0) {
      writeByte((byte) (UINT_TYPE | 0));
    } else if ((diff == 1) && (val[(short) (startOff + index)] < UINT8_LENGTH)
        && (val[(short) (startOff + index)] >= 0)) {
      writeByte((byte) (UINT_TYPE | val[(short) (startOff + index)]));
    } else if (diff == 1) {
      writeByte((byte) (UINT_TYPE | UINT8_LENGTH));
      writeByte(val[(short) (startOff + index)]);
    } else if (diff == 2) {
      writeByte((byte) (UINT_TYPE | UINT16_LENGTH));
      writeBytes(val, (short) (startOff + index), (short) 2);
    } else if (diff <= 4) {
      writeByte((byte) (UINT_TYPE | UINT32_LENGTH));
      writeBytes(val, (short) (startOff + len - 4), (short) 4);
    } else {
      writeByte((byte) (UINT_TYPE | UINT64_LENGTH));
      writeBytes(val, startOff, (short) 8);
    }
  }

  private void encodeByteBlob(short obj) {
    writeMajorTypeWithLength(BYTES_TYPE, KMByteBlob.cast(obj).length());
    writeBytes(KMByteBlob.cast(obj).getBuffer(), KMByteBlob.cast(obj).getStartOff(),
        KMByteBlob.cast(obj).length());
  }

  private void writeByteValue(byte val) {
    if ((val < UINT8_LENGTH) && (val >= 0)) {
      writeByte((byte) (UINT_TYPE | val));
    } else {
      writeByte((byte) (UINT_TYPE | UINT8_LENGTH));
      writeByte((byte) val);
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
