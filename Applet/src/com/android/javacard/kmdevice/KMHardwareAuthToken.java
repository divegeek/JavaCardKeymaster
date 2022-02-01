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
 * KMHardwareAuthToken represents HardwareAuthToken structure from android keymaster hal
 * specifications. It corresponds to CBOR array type. struct{byte HW_AUTH_TOKEN_TYPE; short
 * length=2; short arrayPtr} where arrayPtr is a pointer to ordered array with following elements:
 * {KMInteger Challenge; KMInteger UserId; KMInteger AuthenticatorId; UserAuthType
 * HwAuthenticatorId; KMInteger TimeStamp; KMByteBlob Mac}
 */
public class KMHardwareAuthToken extends KMType {

  public static final byte CHALLENGE = 0x00;
  public static final byte USER_ID = 0x01;
  public static final byte AUTHENTICATOR_ID = 0x02;
  public static final byte HW_AUTHENTICATOR_TYPE = 0x03;
  public static final byte TIMESTAMP = 0x04;
  public static final byte MAC = 0x05;

  private static KMHardwareAuthToken prototype;

  private KMHardwareAuthToken() {
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 6);
    KMArray.add(arrPtr, CHALLENGE, KMInteger.exp());
    KMArray.add(arrPtr, USER_ID, KMInteger.exp());
    KMArray.add(arrPtr, AUTHENTICATOR_ID, KMInteger.exp());
    KMArray.add(arrPtr, HW_AUTHENTICATOR_TYPE, KMEnum.instance(KMType.USER_AUTH_TYPE));
    KMArray.add(arrPtr, TIMESTAMP, KMInteger.exp());
    KMArray.add(arrPtr, MAC, KMByteBlob.exp());
    return instance(arrPtr);
  }

  private static KMHardwareAuthToken proto(short ptr) {
    if (prototype == null) {
      prototype = new KMHardwareAuthToken();
    }
    KMType.instanceTable[KM_HARDWARE_AUTH_TOKEN_OFFSET] = ptr;
    return prototype;
  }

  public static short instance() {
    short arrPtr = KMArray.instance((short) 6);
    KMArray.add(arrPtr, CHALLENGE, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, USER_ID, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, AUTHENTICATOR_ID, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, HW_AUTHENTICATOR_TYPE,
        KMEnum.instance(KMType.USER_AUTH_TYPE, KMType.USER_AUTH_NONE));
    KMArray.add(arrPtr, TIMESTAMP, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, MAC, KMByteBlob.instance((short) 0));
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    if (KMArray.length(vals) != 6) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short ptr = KMType.instance(HW_AUTH_TOKEN_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  private static KMHardwareAuthToken cast(short ptr) {
    if (heap[ptr] != HW_AUTH_TOKEN_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getVals() {
    return Util.getShort(heap,
        (short) (KMType.instanceTable[KM_HARDWARE_AUTH_TOKEN_OFFSET] + TLV_HEADER_SIZE));
  }

  public short length() {
    short arrPtr = getVals();
    return KMArray.length(arrPtr);
  }

  public short getChallenge() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, CHALLENGE);
  }

  public void setChallenge(short vals) {
    KMInteger.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, CHALLENGE, vals);
  }

  public short getUserId() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, USER_ID);
  }

  public void setUserId(short vals) {
    KMInteger.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, USER_ID, vals);
  }

  public short getAuthenticatorId() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, AUTHENTICATOR_ID);
  }

  public void setAuthenticatorId(short vals) {
    KMInteger.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, AUTHENTICATOR_ID, vals);
  }

  public short getHwAuthenticatorType() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, HW_AUTHENTICATOR_TYPE);
  }

  public void setHwAuthenticatorType(short vals) {
    KMEnum.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, HW_AUTHENTICATOR_TYPE, vals);
  }

  public short getTimestamp() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, TIMESTAMP);
  }

  public void setTimestamp(short vals) {
    KMInteger.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, TIMESTAMP, vals);
  }

  public short getMac() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, MAC);
  }

  public void setMac(short vals) {
    KMByteBlob.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, MAC, vals);
  }

  public static short getVals(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getVals();
  }

  public static short length(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).length();
  }

  public static short getChallenge(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getChallenge();
  }

  public static void setChallenge(short bPtr, short vals) {
    KMHardwareAuthToken.cast(bPtr).setChallenge(vals);
  }

  public static short getUserId(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getUserId();
  }

  public static void setUserId(short bPtr, short vals) {
    KMHardwareAuthToken.cast(bPtr).setUserId(vals);
  }

  public static short getAuthenticatorId(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getAuthenticatorId();
  }

  public static void setAuthenticatorId(short bPtr, short vals) {
    KMHardwareAuthToken.cast(bPtr).setAuthenticatorId(vals);
  }

  public static short getHwAuthenticatorType(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getHwAuthenticatorType();
  }

  public static void setHwAuthenticatorType(short bPtr, short vals) {
    KMHardwareAuthToken.cast(bPtr).setHwAuthenticatorType(vals);
  }

  public static short getTimestamp(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getTimestamp();
  }

  public static void setTimestamp(short bPtr, short vals) {
    KMHardwareAuthToken.cast(bPtr).setTimestamp(vals);
  }

  public static short getMac(short bPtr) {
    return KMHardwareAuthToken.cast(bPtr).getMac();
  }

  public static void setMac(short bPtr, short vals) {
    KMHardwareAuthToken.cast(bPtr).setMac(vals);
  }
}
