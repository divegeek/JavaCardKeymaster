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

public class KMHardwareAuthToken extends KMType {
  public static final byte CHALLENGE = 0x00;
  public static final byte USER_ID = 0x01;
  public static final byte AUTHENTICATOR_ID = 0x02;
  public static final byte HW_AUTHENTICATOR_TYPE = 0x03;
  public static final byte TIMESTAMP = 0x04;
  public static final byte MAC = 0x05;

  private KMArray vals;

  private KMHardwareAuthToken() {
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

  public static KMHardwareAuthToken instance() {
    KMHardwareAuthToken inst = repository.newHwAuthToken();
    inst.vals = KMArray.instance((short) 6);
    inst.vals.add(CHALLENGE, KMInteger.instance());
    inst.vals.add(USER_ID, KMInteger.instance());
    inst.vals.add(AUTHENTICATOR_ID, KMInteger.instance());
    inst.vals.add(HW_AUTHENTICATOR_TYPE, KMEnumTag.instance(KMType.USER_AUTH_TYPE));
    inst.vals.add(TIMESTAMP, KMInteger.instance());
    inst.vals.add(MAC, KMByteBlob.instance());
    return inst;
  }

  public static KMHardwareAuthToken instance(KMArray vals) {
    if (vals.length() != 6) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    KMHardwareAuthToken inst = repository.newHwAuthToken();
    inst.vals = vals;
    return inst;
  }

  public static void create(KMHardwareAuthToken[] hwAuthTokenRefTable) {
    byte index = 0;
    while (index < hwAuthTokenRefTable.length) {
      hwAuthTokenRefTable[index] = new KMHardwareAuthToken();
      index++;
    }
  }

  public KMInteger getChallenge() {
    return (KMInteger) vals.get(CHALLENGE);
  }

  public KMInteger getUserId() {
    return (KMInteger) vals.get(USER_ID);
  }

  public KMInteger getAuthenticatorId() {
    return (KMInteger) vals.get(AUTHENTICATOR_ID);
  }

  public byte getHwAuthenticatorType() {
    return ((KMEnumTag) vals.get(HW_AUTHENTICATOR_TYPE)).getValue();
  }

  public KMInteger getTimestamp() {
    return (KMInteger) vals.get(TIMESTAMP);
  }

  public KMByteBlob getMac() {
    return (KMByteBlob) vals.get(MAC);
  }

  public KMArray getVals() {
    return vals;
  }
}
