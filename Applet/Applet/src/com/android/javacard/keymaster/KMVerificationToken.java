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

public class KMVerificationToken extends KMType {
  public static final byte CHALLENGE = 0x00;
  public static final byte TIMESTAMP = 0x01;
  public static final byte PARAMETERS_VERIFIED = 0x02;
  public static final byte SECURITY_LEVEL = 0x03;
  public static final byte MAC = 0x04;

  private static KMVerificationToken prototype;
  private static short instPtr;

  private KMVerificationToken() {}

  public static short exp() {
    short arrPtr = KMArray.instance((short)5);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add(CHALLENGE, KMInteger.exp());
    arr.add(TIMESTAMP, KMInteger.exp());
    //arr.add(PARAMETERS_VERIFIED, KMKeyParameters.exp());
    arr.add(PARAMETERS_VERIFIED, KMByteBlob.exp());
    arr.add(SECURITY_LEVEL, KMEnum.instance(KMType.HARDWARE_TYPE));
    arr.add(MAC, KMByteBlob.exp());
    return instance(arrPtr);
  }

  private static KMVerificationToken proto(short ptr) {
    if (prototype == null) prototype = new KMVerificationToken();
    instPtr = ptr;
    return prototype;
  }


  public static short instance() {
    short arrPtr = KMArray.instance((short)5);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add(CHALLENGE, KMInteger.uint_16((short)0));
    arr.add(TIMESTAMP, KMInteger.uint_16((short)0));
    //arr.add(PARAMETERS_VERIFIED, KMKeyParameters.exp());
    arr.add(PARAMETERS_VERIFIED, KMByteBlob.instance((short)0));
    arr.add(SECURITY_LEVEL, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    arr.add(MAC, KMByteBlob.instance((short)0));
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    KMArray arr = KMArray.cast(vals);
    if(arr.length() != 5)ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    short ptr = KMType.instance(VERIFICATION_TOKEN_TYPE, (short)2);
    Util.setShort(heap, (short)(ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMVerificationToken cast(short ptr) {
    if (heap[ptr] != VERIFICATION_TOKEN_TYPE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
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

  public short getChallenge() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).get(CHALLENGE);
  }

  public void setChallenge(short vals) {
    KMInteger.cast(vals);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(CHALLENGE, vals);
  }

  public short getTimestamp() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).get(TIMESTAMP);
  }

  public void setTimestamp(short vals) {
    KMInteger.cast(vals);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(TIMESTAMP, vals);
  }

  public short getMac() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).get(MAC);
  }

  public void setMac(short vals) {
    KMByteBlob.cast(vals);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(MAC, vals);
  }

  public short getParametersVerified() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).get(PARAMETERS_VERIFIED);
  }

  public void setParametersVerified(short vals) {
   // KMKeyParameters.cast(vals);
    KMByteBlob.cast(vals);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(PARAMETERS_VERIFIED, vals);
  }

  public short getSecurityLevel() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).get(SECURITY_LEVEL);
  }

  public void setSecurityLevel(short vals) {
    KMEnum.cast(vals);
    short arrPtr = getVals();
    KMArray.cast(arrPtr).add(SECURITY_LEVEL, vals);
  }

}
