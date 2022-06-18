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
 * KMArray represents an array of KMTypes. Array is the sequence of elements of one or more sub
 * types of KMType. It also acts as a vector of one subtype of KMTypes on the lines of class
 * KMArray
 * <subType>, where subType is subclass of KMType. Vector is the sequence of elements of one sub
 * type e.g. KMType.BYTE_BLOB_TYPE. The KMArray instance maps to the CBOR type array. KMArray is a
 * KMType and it further extends the value field in TLV_HEADER as ARRAY_HEADER struct{short subType;
 * short length;} followed by sequence of short pointers to KMType instances. The subType can be 0
 * if this is an array or subType is short KMType value e.g. KMType.BYTE_BLOB_TYPE if this is a
 * vector of that sub type.
 */
public class KMArray extends KMType {

  public static final short ANY_ARRAY_LENGTH = 0x1000;
  private static final short ARRAY_HEADER_SIZE = 4;
  private static KMArray prototype;

  private KMArray() {
  }

  private static KMArray proto(short ptr) {
    if (prototype == null) {
      prototype = new KMArray();
    }
    instanceTable[KM_ARRAY_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short ptr = instance(ARRAY_TYPE, ARRAY_HEADER_SIZE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), ANY_ARRAY_LENGTH);
    return ptr;
  }

  public static short exp(short type) {
    short ptr = instance(ARRAY_TYPE, ARRAY_HEADER_SIZE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), ANY_ARRAY_LENGTH);
    return ptr;
  }

  public static short instance(short length) {
    short ptr = KMType.instance(ARRAY_TYPE, (short) (ARRAY_HEADER_SIZE + (length * 2)));
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), length);
    return ptr;
  }

  public static short instance(short length, byte type) {
    short ptr = instance(length);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
    return ptr;
  }

  public static KMArray cast(short ptr) {
    if (heap[ptr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public void add(short index, short objPtr) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.setShort(
      heap,
      (short) (instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + ARRAY_HEADER_SIZE + (short) (index * 2)),
      objPtr);
  }

  public short get(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return Util.getShort(
      heap, (short) (instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + ARRAY_HEADER_SIZE + (short) (index * 2)));
  }

  public short containedType() {
    return Util.getShort(heap, (short) (instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE));
  }

  public short getStartOff() {
    return (short) (instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + ARRAY_HEADER_SIZE);
  }

  public short length() {
    return Util.getShort(heap, (short) (instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  public short setLength(short len) {
    return Util.setShort(heap,
	        (short) (KMType.instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + 2), len);
  }

  public byte[] getBuffer() {
    return heap;
  }
}
