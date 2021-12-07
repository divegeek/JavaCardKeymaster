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
import javacard.framework.Util;

/**
 * Represents 8 bit, 16 bit, 32 bit and 64 bit unsigned integer. It corresponds to CBOR uint type.
 * struct{byte INTEGER_TYPE; short length; 4 or 8 bytes of value}
 */
public class KMInteger extends KMType {

  public static final short UINT_32 = 4;
  public static final short UINT_64 = 8;
  private static KMInteger prototype;

  private KMInteger() {
  }

  private static KMInteger proto(short ptr) {
    if (prototype == null) {
      prototype = new KMInteger();
    }
    instanceTable[KM_INTEGER_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    return KMType.exp(INTEGER_TYPE);
  }

  // return an empty integer instance
  public static short instance(short length) {
    if ((length <= 0) || (length > 8)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (length > 4) {
      length = UINT_64;
    } else {
      length = UINT_32;
    }
    return KMType.instance(INTEGER_TYPE, length);
  }

  public static short instance(byte[] num, short srcOff, short length) {
    if (length > 8) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (length == 1) {
      return uint_8(num[srcOff]);
    } else if (length == 2) {
      return uint_16(Util.getShort(num, srcOff));
    } else if (length == 4) {
      return uint_32(num, srcOff);
    } else {
      return uint_64(num, srcOff);
    }
  }

  public static KMInteger cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != INTEGER_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  // create integer and copy byte value
  public static short uint_8(byte num) {
    short ptr = instance(UINT_32);
    heap[(short) (ptr + TLV_HEADER_SIZE + 3)] = num;
    return ptr;
  }

  // create integer and copy short value
  public static short uint_16(short num) {
    short ptr = instance(UINT_32);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), num);
    return ptr;
  }

  // create integer and copy integer value
  public static short uint_32(byte[] num, short offset) {
    short ptr = instance(UINT_32);
    Util.arrayCopyNonAtomic(num, offset, heap, (short) (ptr + TLV_HEADER_SIZE), UINT_32);
    return ptr;
  }

  // create integer and copy integer value
  public static short uint_64(byte[] num, short offset) {
    short ptr = instance(UINT_64);
    Util.arrayCopyNonAtomic(num, offset, heap, (short) (ptr + TLV_HEADER_SIZE), UINT_64);
    return ptr;
  }

  // Get the length of the integer
  public short length() {
    return Util.getShort(heap, (short) (instanceTable[KM_INTEGER_OFFSET] + 1));
  }

  // Get the buffer pointer in which blob is contained.
  public byte[] getBuffer() {
    return heap;
  }

  // Get the start of value
  public short getStartOff() {
    return (short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE);
  }

  public void getValue(byte[] dest, short destOff, short length) {
    if (length < length()) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (length > length()) {
      length = length();
      destOff += length;
    }
    Util.arrayCopyNonAtomic(heap, (short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE), dest, destOff, length);
  }

  public void setValue(byte[] src, short srcOff) {
    Util.arrayCopyNonAtomic(src, srcOff, heap, (short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE), length());
  }

  public short value(byte[] dest, short destOff) {
    Util.arrayCopyNonAtomic(heap, (short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE), dest, destOff, length());
    return length();
  }

  public short toLittleEndian(byte[] dest, short destOff) {
    short index = (short) (length() - 1);
    while (index >= 0) {
      dest[destOff++] = heap[(short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE + index)];
      index--;
    }
    return length();
  }

  public short getShort() {
    return Util.getShort(heap, (short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  public short getSignificantShort() {
    return Util.getShort(heap, (short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE));
  }

  public byte getByte() {
    return heap[(short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE + 3)];
  }

  public boolean isZero() {
    if (getShort() == 0 && getSignificantShort() == 0) {
      return true;
    }
    return false;
  }

  public static short compare(short num1, short num2) {
    short num1Buf = repository.alloc((short) 8);
    short num2Buf = repository.alloc((short) 8);
    Util.arrayFillNonAtomic(repository.getHeap(), num1Buf, (short) 8, (byte) 0);
    Util.arrayFillNonAtomic(repository.getHeap(), num2Buf, (short) 8, (byte) 0);
    short len = KMInteger.cast(num1).length();
    KMInteger.cast(num1).getValue(repository.getHeap(), (short) (num1Buf + (short) (8 - len)), len);
    len = KMInteger.cast(num2).length();
    KMInteger.cast(num2).getValue(repository.getHeap(), (short) (num2Buf + (short) (8 - len)), len);
    return KMInteger.unsignedByteArrayCompare(
      repository.getHeap(), num1Buf,
      repository.getHeap(), num2Buf,
      (short) 8);
  }

  public static byte unsignedByteArrayCompare(byte[] a1, short offset1, byte[] a2, short offset2,
                                              short length) {
    byte count = (byte) 0;
    short val1 = (short) 0;
    short val2 = (short) 0;

    for (; count < length; count++) {
      val1 = (short) (a1[(short) (count + offset1)] & 0x00FF);
      val2 = (short) (a2[(short) (count + offset2)] & 0x00FF);

      if (val1 < val2) {
        return -1;
      }
      if (val1 > val2) {
        return 1;
      }
    }
    return 0;
  }
}
