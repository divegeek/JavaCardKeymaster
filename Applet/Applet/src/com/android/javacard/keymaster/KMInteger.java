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

// Represents 8 bit, 16 bit, 32 bit and 64 bit integers
public class KMInteger extends KMType {
  private byte[] val;

  private KMInteger() {
    init();
  }

  @Override
  public void init() {
    val = null;
  }

  @Override
  public short length() {
    return (short) this.val.length;
  }

  public static KMInteger instance() {
    return repository.newInteger();
  }

  // create integer and copy byte value
  public static KMInteger uint_8(byte num) {
    KMInteger inst = repository.newInteger();
    inst.val = repository.newIntegerArray((short) 4);
    inst.val[3] = num;
    return inst;
  }

  // create integer and copy short value
  public static KMInteger uint_16(short num) {
    KMInteger inst = repository.newInteger();
    inst.val = repository.newIntegerArray((short) 4);
    inst.val[2] = (byte) ((num >> 8) & 0xff);
    inst.val[3] = (byte) (num & 0xff);
    return inst;
  }

  // create integer and copy integer value
  public static KMInteger uint_32(byte[] num, short offset) {
    KMInteger inst = repository.newInteger();
    inst.val = repository.newIntegerArray((short) 4);
    Util.arrayCopy(num, offset, inst.val, (short) 0, (short) 4);
    return inst;
  }

  // create integer and copy integer value
  public static KMInteger uint_64(byte[] num, short offset) {
    KMInteger inst = repository.newInteger();
    inst.val = repository.newIntegerArray((short) 8);
    Util.arrayCopy(num, offset, inst.val, (short) 0, (short) 8);
    return inst;
  }

  public static void create(KMInteger[] integerRefTable) {
    byte index = 0;
    while (index < integerRefTable.length) {
      integerRefTable[index] = new KMInteger();
      index++;
    }
  }

  public byte[] getValue() {
    return val;
  }

  public KMInteger setValue(short val) {
    this.val[2] = (byte) (val >> 8);
    this.val[3] = (byte) (val & 0xFF);
    return this;
  }

  public KMInteger setValue(byte[] val) {
    this.val = val;
    return this;
  }

  public short getShort() {
    if (val == null) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    } else if (val.length != 4) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    return Util.makeShort(val[2], val[3]);
  }

  public byte getByte() {
    if (val == null) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    } else if (val.length != 4) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    return val[3];
  }

  // copy the integer value from bytes
  public static KMInteger instance(byte[] num, short srcOff, short length) {
    if (length == 1) {
      return uint_8(num[srcOff]);
    } else if (length == 2) {
      return uint_16(Util.makeShort(num[srcOff], num[(short) (srcOff + 1)]));
    } else if (length == 4) {
      return uint_32(num, srcOff);
    } else if (length == 8) {
      return uint_64(num, srcOff);
    } else {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
  }
}
