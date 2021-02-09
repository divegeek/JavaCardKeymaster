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
 * KMKeyCharacteristics represents KeyCharacteristics structure from android keymaster hal specifications.
 * It corresponds to CBOR array type.
 * struct{byte KEY_CHAR_TYPE; short length=2; short arrayPtr} where arrayPtr is a pointer to
 * ordered array with following elements:
 * {KMKeyParameters sofEnf; KMKeyParameters hwEnf}
 */
public class KMKeyCharacteristics extends KMType {
  public static final byte SOFTWARE_ENFORCED = 0x00;
  public static final byte HARDWARE_ENFORCED = 0x01;
  private static KMKeyCharacteristics prototype;
  private static short instPtr;

  private KMKeyCharacteristics() {}

  public static short exp() {
    short softEnf = KMKeyParameters.exp();
    short hwEnf = KMKeyParameters.exp();
    short arrPtr = KMArray.instance((short)2);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add(SOFTWARE_ENFORCED, softEnf);
    arr.add(HARDWARE_ENFORCED, hwEnf);
    return instance(arrPtr);
  }

  private static KMKeyCharacteristics proto(short ptr) {
    if (prototype == null) prototype = new KMKeyCharacteristics();
    instPtr = ptr;
    return prototype;
  }

  public static short instance() {
    short arrPtr = KMArray.instance((short)2);
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    short ptr = KMType.instance(KEY_CHAR_TYPE, (short)2);
    if(KMArray.cast(vals).length() != 2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    Util.setShort(heap, (short)(ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMKeyCharacteristics cast(short ptr) {
    if (heap[ptr] != KEY_CHAR_TYPE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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

  public short getSoftwareEnforced() {
    short arrPtr = getVals();
    return  KMArray.cast(arrPtr).get(SOFTWARE_ENFORCED);
  }

  public short getHardwareEnforced() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).get(HARDWARE_ENFORCED);
  }

  public void setSoftwareEnforced(short ptr) {
    KMKeyParameters.cast(ptr);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(SOFTWARE_ENFORCED, ptr);
  }

  public void setHardwareEnforced(short ptr) {
    KMKeyParameters.cast(ptr);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(HARDWARE_ENFORCED, ptr);
  }
}
