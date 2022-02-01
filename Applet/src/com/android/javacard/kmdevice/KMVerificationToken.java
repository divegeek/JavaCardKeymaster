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
 * KMVerificationToken represents VerificationToken structure from android keymaster hal
 * specifications. It corresponds to CBOR array type. struct{byte type=VERIFICATION_TOKEN_TYPE;
 * short length=2; short arrayPtr} where arrayPtr is a pointer to ordered array with following
 * elements: {KMInteger Challenge; KMInteger Timestamp; KMByteBlob PARAMETERS_VERIFIED;
 * SecurityLevel level; KMByteBlob Mac}.
 */
public class KMVerificationToken extends KMType {

  public static final byte CHALLENGE = 0x00;
  public static final byte TIMESTAMP = 0x01;
  public static final byte PARAMETERS_VERIFIED = 0x02;
  public static final byte SECURITY_LEVEL = 0x03;
  public static final byte MAC1 = 0x02;
  public static final byte MAC2 = 0x04;

  private static KMVerificationToken prototype;

  private KMVerificationToken() {
  }

  public static short timeStampTokenExp() {
    short arrPtr = KMArray.instance((short) 3);
    KMArray.add(arrPtr, CHALLENGE, KMInteger.exp());
    KMArray.add(arrPtr, TIMESTAMP, KMInteger.exp());
    KMArray.add(arrPtr, MAC1, KMByteBlob.exp());
    return instance(arrPtr);
  }

  public static short verificationTokenExp() {
    short arrPtr = KMArray.instance((short) 5);
    KMArray.add(arrPtr, CHALLENGE, KMInteger.exp());
    KMArray.add(arrPtr, TIMESTAMP, KMInteger.exp());
    //arr.add(PARAMETERS_VERIFIED, KMKeyParameters.exp());
    KMArray.add(arrPtr, PARAMETERS_VERIFIED, KMByteBlob.exp());
    KMArray.add(arrPtr, SECURITY_LEVEL, KMEnum.instance(KMType.HARDWARE_TYPE));
    KMArray.add(arrPtr, MAC2, KMByteBlob.exp());
    return instance(arrPtr);
  }

  private static KMVerificationToken proto(short ptr) {
    if (prototype == null) {
      prototype = new KMVerificationToken();
    }
    KMType.instanceTable[KM_VERIFICATION_TOKEN_OFFSET] = ptr;
    return prototype;
  }

  public static short instance1() {
    short arrPtr = KMArray.instance((short) 3);
    KMArray.add(arrPtr, CHALLENGE, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, TIMESTAMP, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, MAC1, KMByteBlob.instance((short) 0));
    return instance(arrPtr);
  }

  public static short instance2() {
    short arrPtr = KMArray.instance((short) 5);
    KMArray.add(arrPtr, CHALLENGE, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, TIMESTAMP, KMInteger.uint_16((short) 0));
    KMArray.add(arrPtr, PARAMETERS_VERIFIED, KMByteBlob.instance((short) 0));
    KMArray.add(arrPtr, SECURITY_LEVEL, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    KMArray.add(arrPtr, MAC2, KMByteBlob.instance((short) 0));
    return instance(arrPtr);
  }

  public static short instance(short vals) {
    if (KMArray.length(vals) != 3 && KMArray.length(vals) != 5) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short ptr = KMType.instance(VERIFICATION_TOKEN_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  private static KMVerificationToken cast(short ptr) {
    if (heap[ptr] != VERIFICATION_TOKEN_TYPE) {
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
        (short) (KMType.instanceTable[KM_VERIFICATION_TOKEN_OFFSET] + TLV_HEADER_SIZE));
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

  public short getTimestamp() {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, TIMESTAMP);
  }

  public void setTimestamp(short vals) {
    KMInteger.validate(vals);
    short arrPtr = getVals();
    KMArray.add(arrPtr, TIMESTAMP, vals);
  }

  public short getMac(short macIndex) {
    short arrPtr = getVals();
    return KMArray.get(arrPtr, macIndex);
  }


  public static short getVals(short bPtr) {
    return KMVerificationToken.cast(bPtr).getVals();
  }

  public static short length(short bPtr) {
    return KMVerificationToken.cast(bPtr).length();
  }

  public static short getChallenge(short bPtr) {
    return KMVerificationToken.cast(bPtr).getChallenge();
  }

  public static void setChallenge(short bPtr, short vals) {
    KMVerificationToken.cast(bPtr).setChallenge(vals);
  }

  public static short getTimestamp(short bPtr) {
    return KMVerificationToken.cast(bPtr).getTimestamp();
  }

  public static void setTimestamp(short bPtr, short vals) {
    KMVerificationToken.cast(bPtr).setTimestamp(vals);
  }

  public static short getMac(short bPtr, short macIndex) {
    return KMVerificationToken.cast(bPtr).getMac(macIndex);
  }

}
