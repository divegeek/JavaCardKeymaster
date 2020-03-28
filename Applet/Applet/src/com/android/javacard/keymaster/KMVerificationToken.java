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

public class KMVerificationToken extends KMType {
  public static final byte CHALLENGE = 0x00;
  public static final byte TIMESTAMP = 0x01;
  public static final byte PARAMETERS_VERIFIED = 0x02;
  public static final byte SECURITY_LEVEL = 0x03;
  public static final byte MAC = 0x04;
  private KMArray vals;

  private KMVerificationToken() {
    init();
  }

  @Override
  public void init() {
    vals = null;
  }

  @Override
  public short length() {
    return vals.length();
  }

  public static void create(KMVerificationToken[] verTokenRefTable) {
    byte index = 0;
    while (index < verTokenRefTable.length) {
      verTokenRefTable[index] = new KMVerificationToken();
      index++;
    }
  }

  public static KMVerificationToken instance() {
    KMVerificationToken inst = repository.newVerificationToken();
    inst.vals = KMArray.instance((short) 5);
    inst.vals.add(CHALLENGE, KMInteger.instance());
    inst.vals.add(TIMESTAMP, KMInteger.instance());
    inst.vals.add(PARAMETERS_VERIFIED, KMKeyParameters.instance());
    inst.vals.add(SECURITY_LEVEL, KMEnumTag.instance(KMType.HARDWARE_TYPE));
    inst.vals.add(MAC, KMByteBlob.instance());
    return inst;
  }

  public static KMVerificationToken instance(KMArray vals) {
    if (vals.length() != 5) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    KMVerificationToken inst = repository.newVerificationToken();
    inst.vals = vals;
    return inst;
  }

  public KMInteger getChallenge() {
    return (KMInteger) vals.get(CHALLENGE);
  }

  public KMInteger getTimestamp() {
    return (KMInteger) vals.get(TIMESTAMP);
  }

  public KMKeyParameters getParametersVerified() {
    return (KMKeyParameters) vals.get(PARAMETERS_VERIFIED);
  }

  public byte getSecurityLevel() {
    return ((KMEnumTag) vals.get(SECURITY_LEVEL)).getValue();
  }

  public KMByteBlob getMac() {
    return (KMByteBlob) vals.get(MAC);
  }

  public KMArray getVals() {
    return vals;
  }
}
