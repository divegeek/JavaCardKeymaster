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

package com.android.javacard.kmdevice;

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

  protected KMInteger() {
  }

  private static KMInteger proto(short ptr) {
    if (prototype == null) {
      prototype = new KMInteger();
    }
    KMType.instanceTable[KM_INTEGER_OFFSET] = ptr;
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

  private static KMInteger cast(short ptr) {
    validate(ptr);
    return proto(ptr);
  }

  public static void validate(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != INTEGER_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
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
    Util.arrayCopy(num, offset, heap, (short) (ptr + TLV_HEADER_SIZE), UINT_32);
    return ptr;
  }

  // create integer and copy integer value
  public static short uint_64(byte[] num, short offset) {
    short ptr = instance(UINT_64);
    Util.arrayCopy(num, offset, heap, (short) (ptr + TLV_HEADER_SIZE), UINT_64);
    return ptr;
  }

  // Get the length of the integer
  private short length() {
    return Util.getShort(heap, (short) (getBaseOffset() + 1));
  }

  // Get the buffer pointer in which blob is contained.
  private byte[] getBuffer() {
    return heap;
  }

  // Get the start of value
  private short getStartOff() {
    return (short) (getBaseOffset() + TLV_HEADER_SIZE);
  }

  private void getValue(byte[] dest, short destOff, short length) {
    if (length < length()) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (length > length()) {
      length = length();
      destOff += length;
    }
    Util.arrayCopyNonAtomic(heap, getStartOff(), dest, destOff, length);
  }

  private void setValue(byte[] src, short srcOff) {
    Util.arrayCopyNonAtomic(src, srcOff, heap, getStartOff(), length());
  }

  private short value(byte[] dest, short destOff) {
    Util.arrayCopyNonAtomic(heap, getStartOff(), dest, destOff, length());
    return length();
  }

  private short toLittleEndian(byte[] dest, short destOff) {
    short index = (short) (length() - 1);
    while (index >= 0) {
      dest[destOff++] = heap[(short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE + index)];
      index--;
    }
    return length();
  }

  protected short getShort() {
    return Util.getShort(heap, (short) (getStartOff() + 2));
  }

  private short getSignificantShort() {
    return Util.getShort(heap, getStartOff());
  }

  private byte getByte() {
    return heap[(short) (getStartOff() + 3)];
  }

  private boolean isZero() {
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
    short len = KMInteger.length(num1);
    KMInteger.getValue(num1, repository.getHeap(), (short) (num1Buf + (short) (8 - len)), len);
    len = KMInteger.length(num2);
    KMInteger.getValue(num2, repository.getHeap(), (short) (num2Buf + (short) (8 - len)), len);
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

  protected short getBaseOffset() {
    return instanceTable[KM_INTEGER_OFFSET];
  }

  // Get the length of the integer
  public static short length(short bPtr) {
    return KMInteger.cast(bPtr).length();
  }

  // Get the buffer pointer in which blob is contained.
  public static byte[] getBuffer(short bPtr) {
    return KMInteger.cast(bPtr).getBuffer();
  }

  // Get the start of value
  public static short getStartOff(short bPtr) {
    return KMInteger.cast(bPtr).getStartOff();
  }

  public static void getValue(short bPtr, byte[] dest, short destOff, short length) {
    KMInteger.cast(bPtr).getValue(dest, destOff, length);
  }

  public static void setValue(short bPtr, byte[] src, short srcOff) {
    KMInteger.cast(bPtr).setValue(src, srcOff);
  }

  public static short value(short bPtr, byte[] dest, short destOff) {
    return KMInteger.cast(bPtr).value(dest, destOff);
  }

  public static short toLittleEndian(short bPtr, byte[] dest, short destOff) {
    return KMInteger.cast(bPtr).toLittleEndian(dest, destOff);
  }

  public static short getShort(short bPtr) {
    return KMInteger.cast(bPtr).getShort();
  }

  public static short getSignificantShort(short bPtr) {
    return KMInteger.cast(bPtr).getSignificantShort();
  }

  public static byte getByte(short bPtr) {
    return KMInteger.cast(bPtr).getByte();
  }

  public static boolean isZero(short bPtr) {
    return KMInteger.cast(bPtr).isZero();
  }
}
