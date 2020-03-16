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
import javacard.framework.Util;
// TODO Clean and refactor the code.
public class KMDecoder {
  // major types
  private static final short UINT_TYPE = 0x00;
  private static final short BYTES_TYPE = 0x40;
  private static final short ARRAY_TYPE = 0x80;
  private static final short MAP_TYPE =  0xA0;

  // masks
  private static final short ADDITIONAL_MASK = 0x1F;
  private static final short MAJOR_TYPE_MASK = 0xE0;

  // value length
  private static final short UINT8_LENGTH =  0x18;
  private static final short UINT16_LENGTH =  0x19;
  private static final short UINT32_LENGTH = 0x1A;
  private static final short UINT64_LENGTH =  0x1B;

  // TODO move the following to transient memory.
  private byte[] buffer;
  private short startOff;
  private short length;
  private short tagType;
  private short tagKey;

  public KMDecoder() {
    buffer = null;
    startOff = 0;
    length = 0;
  }

  public KMArray decode(KMArray expression, byte[] buffer, short startOff, short length) {
    this.buffer = buffer;
    this.startOff = startOff;
    this.length = length;
    return decode(expression);
  }

  private KMEnumArrayTag decode(KMEnumArrayTag exp) {
    readTagKey(exp.getTagType());
    // The value must be byte blob
    // TODO check this out.
    return exp.instance(this.tagKey, decode(exp.getValues()));
  }

  private KMIntegerArrayTag decode(KMIntegerArrayTag exp) {
    readTagKey(exp.getTagType());
    // the values are array of integers.
    if (!(exp.getValues().getType() instanceof KMInteger)) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    return exp.instance(this.tagKey, decode(exp.getValues(), (KMInteger) exp.getValues().getType()));
  }

  private KMIntegerTag decode(KMIntegerTag exp) {
    readTagKey(exp.getTagType());
    // the value is an integer
    return exp.instance(this.tagKey, decode(exp.getValue()));
  }

  private KMByteTag decode(KMByteTag exp) {
    short key = 0;
    readTagKey(exp.getTagType());
    // The value must be byte blob
    return exp.instance(this.tagKey, decode(exp.getValue()));
  }

  private KMBoolTag decode(KMBoolTag exp) {
    readTagKey(exp.getTagType());
    // BOOL Tag is a leaf node and it must always have tiny encoded uint value = 1.
    // TODO check this out.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    if ((byte) (buffer[startOff] & ADDITIONAL_MASK) != 0x01) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    incrementStartOff((short) 1);
    return exp.instance(tagKey);
  }

  private KMEnumTag decode(KMEnumTag exp) {
    readTagKey(exp.getTagType());
    // Enum Tag value will always be integer with max 1 byte length.
    // TODO Check this out.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    byte enumVal = 0;
    if (len > UINT8_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    if (len < UINT8_LENGTH) {
      enumVal = (byte)(len & ADDITIONAL_MASK);
      incrementStartOff((short) 1);
    } else if (len == UINT8_LENGTH) {
      incrementStartOff((short) 1);
      enumVal = buffer[startOff];
      incrementStartOff((short) 1);
    }
    return exp.instance(tagKey, enumVal);
  }

  private KMEnum decode(KMEnum exp) {

    // Enum value will always be integer with max 1 byte length.
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    byte enumVal = 0;
    if (len > UINT8_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    if (len < UINT8_LENGTH) {
      enumVal = (byte)(len & ADDITIONAL_MASK);
      incrementStartOff((short) 1);
    } else {
      incrementStartOff((short) 1);
      enumVal = buffer[startOff];
      incrementStartOff((short) 1);
    }
    return exp.instance(exp.getType(), enumVal);
  }

  private KMInteger decode(KMInteger exp) {
    KMInteger inst;
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    short len = (short) (buffer[startOff] & ADDITIONAL_MASK);
    incrementStartOff((short) 1);
    if (len < UINT8_LENGTH) {
      inst = exp.uint_8((byte)(len & ADDITIONAL_MASK));
    } else if (len == UINT8_LENGTH) {
      inst = exp.instance(buffer, startOff, (short) 1);
      incrementStartOff((short) 1);
    } else if (len == UINT16_LENGTH) {
      inst = exp.instance(buffer, startOff, (short) 2);
      incrementStartOff((short) 2);
    } else if (len == UINT32_LENGTH) {
      inst = exp.instance(buffer, startOff, (short) 4);
      incrementStartOff((short) 4);
    } else if (len == UINT64_LENGTH) {
      inst = exp.instance(buffer, startOff, (short) 8);
      incrementStartOff((short) 8);
    } else {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    return inst;
  }

  private KMByteBlob decode(KMByteBlob exp) {
    short payloadLength = readMajorTypeWithPayloadLength(BYTES_TYPE);
    KMByteBlob inst = exp.instance(buffer, startOff, payloadLength);
    incrementStartOff(payloadLength);
    return inst;
  }

  private KMArray decode(KMArray exp) {
    short payloadLength = readMajorTypeWithPayloadLength(ARRAY_TYPE);
    if (exp.length() != payloadLength) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    KMArray inst = exp.instance(payloadLength);
    short index = 0;
    while (index < payloadLength) {
      KMType type = exp.get(index);
      inst.add(index, decode(type));
      index++;
    }
    return inst;
  }

  private KMVector decode(KMVector exp, KMInteger type) {
    short payloadLength = readMajorTypeWithPayloadLength(ARRAY_TYPE);
    KMVector inst = exp.instance(type, payloadLength);
    short index = 0;
    while (index < payloadLength) {
      inst.add(index, decode(type));
      index++;
    }
    return inst;
  }

  private KMVerificationToken decode(KMVerificationToken exp) {
    KMArray vals = decode(exp.getVals());
    return exp.instance(vals);
  }

  private KMHardwareAuthToken decode(KMHardwareAuthToken exp) {
    KMArray vals = decode(exp.getVals());
    return exp.instance(vals);
  }

  private KMHmacSharingParameters decode(KMHmacSharingParameters exp) {
    KMArray vals = decode(exp.getVals());
    return exp.instance(vals);
  }

  private KMKeyParameters decode(KMKeyParameters exp) {
    short payloadLength = readMajorTypeWithPayloadLength(MAP_TYPE);
    // allowed tags
    // TODO expand the logic to handle prototypes with tag values also.
    KMArray allowedTags = exp.getVals();
    KMArray vals = KMArray.instance(payloadLength);
    short index = 0;
    while (index < payloadLength) {
      short tagInd = 0;
      short tagType = peekTagType();
      while (tagInd < allowedTags.length()) {
        KMTag tagClass = ((KMTag) allowedTags.get(tagInd));
        short allowedType = ((KMTag) allowedTags.get(tagInd)).getTagType();
        if (tagType == allowedType) {
          vals.add(index, decode(tagClass));
          break;
        }
        tagInd++;
      }
      index++;
    }
    return KMKeyParameters.instance(vals);
  }

  private KMKeyCharacteristics decode(KMKeyCharacteristics exp) {
    KMArray vals = decode(exp.getVals());
    return exp.instance(vals);
  }

  private KMType decode(KMType exp) {
    if (exp instanceof KMByteBlob) {
      return decode((KMByteBlob) exp);
    }
    if (exp instanceof KMInteger) {
      return decode((KMInteger) exp);
    }
    if (exp instanceof KMArray) {
      return decode((KMArray) exp);
    }
    if (exp instanceof KMVector) {
      if (!((((KMVector) exp).getType()) instanceof KMInteger)) {
        throw new KMException(ISO7816.SW_DATA_INVALID);
      }
      return decode((KMVector) exp, (KMInteger) ((KMVector) exp).getType());
    }
    if (exp instanceof KMByteTag) {
      return decode((KMByteTag) exp);
    }
    if (exp instanceof KMBoolTag) {
      return decode((KMBoolTag) exp);
    }
    if (exp instanceof KMIntegerTag) {
      return decode((KMIntegerTag) exp);
    }
    if (exp instanceof KMIntegerArrayTag) {
      return decode((KMIntegerArrayTag) exp);
    }
    if (exp instanceof KMEnumTag) {
      return decode((KMEnumTag) exp);
    }
    if (exp instanceof KMEnum) {
      return decode((KMEnum) exp);
    }
    if (exp instanceof KMEnumArrayTag) {
      return decode((KMEnumArrayTag) exp);
    }
    if (exp instanceof KMKeyParameters) {
      return decode((KMKeyParameters) exp);
    }
    if (exp instanceof KMKeyCharacteristics) {
      return decode((KMKeyCharacteristics) exp);
    }
    if (exp instanceof KMVerificationToken) {
      return decode((KMVerificationToken) exp);
    }
    if (exp instanceof KMHmacSharingParameters) {
      return decode((KMHmacSharingParameters) exp);
    }
    if (exp instanceof KMHardwareAuthToken) {
      return decode((KMHardwareAuthToken) exp);
    }
    throw new KMException(ISO7816.SW_DATA_INVALID);
  }

  private short peekTagType() {
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }

    if ((short) (buffer[startOff] & ADDITIONAL_MASK) != UINT32_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    return (short)
        ((Util.makeShort(buffer[(short) (startOff + 1)], buffer[(short) (startOff + 2)]))
            & KMType.TAG_TYPE_MASK);
  }

  private void readTagKey(short expectedTagType) {
    if ((buffer[startOff] & MAJOR_TYPE_MASK) != UINT_TYPE) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    if ((byte) (buffer[startOff] & ADDITIONAL_MASK) != UINT32_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    incrementStartOff((short) 1);
    this.tagType = readShort();
    this.tagKey = readShort();
    if (tagType != expectedTagType) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
  }

  // payload length cannot be more then 16 bits.
  private short readMajorTypeWithPayloadLength(short majorType) {
    short payloadLength = 0;
    byte val = readByte();
    if ((short) (val & MAJOR_TYPE_MASK) != majorType) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    short lenType = (short) (val & ADDITIONAL_MASK);
    if (lenType > UINT16_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    if (lenType < UINT8_LENGTH) {
      payloadLength = lenType;
    }else if (lenType == UINT8_LENGTH) {
      payloadLength = (short)(readByte() & 0xFF);
    } else {
      payloadLength = readShort();
    }
    return payloadLength;
  }

  private short readShort() {
    short val = Util.makeShort(buffer[startOff], buffer[(short) (startOff + 1)]);
    incrementStartOff((short) 2);
    return val;
  }

  private byte readByte() {
    byte val = buffer[startOff];
    incrementStartOff((short) 1);
    return val;
  }

  private void incrementStartOff(short inc) {
    startOff += inc;
    if (startOff > this.length) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
  }
}
