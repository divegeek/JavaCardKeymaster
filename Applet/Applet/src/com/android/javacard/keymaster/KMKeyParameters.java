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

public class KMKeyParameters extends KMType {
  private static KMKeyParameters prototype;
  private static short instPtr;

  private KMKeyParameters() {}

  private static KMKeyParameters proto(short ptr) {
    if (prototype == null) prototype = new KMKeyParameters();
    instPtr = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short)9);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMIntegerTag.exp(UINT_TAG));
    arr.add((short) 1, KMIntegerArrayTag.exp(UINT_ARRAY_TAG));
    arr.add((short) 2, KMIntegerTag.exp(ULONG_TAG));
    arr.add((short) 3, KMIntegerTag.exp(DATE_TAG));
    arr.add((short) 4, KMIntegerArrayTag.exp(ULONG_ARRAY_TAG));
    arr.add((short) 5, KMEnumTag.exp());
    arr.add((short) 6, KMEnumArrayTag.exp());
    arr.add((short) 7, KMByteTag.exp());
    arr.add((short) 8, KMBoolTag.exp());
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(KEY_PARAM_TYPE, (short)2);
    Util.setShort(heap, (short)(ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMKeyParameters cast(short ptr) {
    if (heap[ptr] != KEY_PARAM_TYPE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if(heap[arrPtr] != ARRAY_TYPE)  ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    return proto(ptr);
  }

  public short getVals() {
    return Util.getShort(heap, (short) (instPtr + TLV_HEADER_SIZE));
  }

  public short length() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).length();
  }

}
