/*
 * Copyright(C) 2021 The Android Open Source Project
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

public class KMMap extends KMType {
  public static final short ANY_MAP_LENGTH = 0x1000;
  private static final short MAP_HEADER_SIZE = 4;
  private static KMMap prototype;

  private KMMap() {
  }

  private static KMMap proto(short ptr) {
    if (prototype == null) {
      prototype = new KMMap();
    }
    instanceTable[KM_MAP_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short ptr = instance(MAP_TYPE, MAP_HEADER_SIZE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), ANY_MAP_LENGTH);
    return ptr;
  }

  public static short instance(short length) {
    short ptr = KMType.instance(MAP_TYPE, (short) (MAP_HEADER_SIZE + (length * 4)));
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), length);
    return ptr;
  }

  public static short instance(short length, byte type) {
    short ptr = instance(length);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
    return ptr;
  }

  public static KMMap cast(short ptr) {
    if (heap[ptr] != MAP_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public void add(short index, short keyPtr, short valPtr) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short keyIndex = (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index * 4));
    Util.setShort(heap, keyIndex, keyPtr);
    Util.setShort(heap, (short) (keyIndex + 2), valPtr);
  }

  public short getKey(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return Util.getShort(
      heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index * 4)));
  }

  public short getKeyValue(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return Util.getShort(
      heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index * 4 + 2)));
  }

  public void swap(short index1, short index2) {
    short len = length();
    if (index1 >= len || index2 >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Swap keys
    short indexPtr1 =
      Util.getShort(
        heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index1 * 4)));
    short indexPtr2 =
      Util.getShort(
        heap,
        (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index2 * 4)));
    Util.setShort(
      heap,
      (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index1 * 4)),
      indexPtr2);
    Util.setShort(
      heap,
      (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index2 * 4)),
      indexPtr1);

    // Swap Values
    indexPtr1 =
      Util.getShort(
        heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index1 * 4 + 2)));
    indexPtr2 =
      Util.getShort(
        heap,
        (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index2 * 4 + 2)));
    Util.setShort(
      heap,
      (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index1 * 4 + 2)),
      indexPtr2);
    Util.setShort(
      heap,
      (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE + (short) (index2 * 4 + 2)),
      indexPtr1);
  }

  public void canonicalize() {
    KMCoseMap.canonicalize(instanceTable[KM_MAP_OFFSET], length());
  }

  public short containedType() {
    return Util.getShort(heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE));
  }

  public short getStartOff() {
    return (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE);
  }

  public short length() {
    return Util.getShort(heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  public byte[] getBuffer() {
    return heap;
  }
}
