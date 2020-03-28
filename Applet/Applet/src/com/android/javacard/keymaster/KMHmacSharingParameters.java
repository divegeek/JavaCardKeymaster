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

public class KMHmacSharingParameters extends KMType {
  public static final byte SEED = 0x00;
  public static final byte NONCE = 0x01;
  private KMArray vals;

  private KMHmacSharingParameters() {
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

  public static KMHmacSharingParameters instance() {
    KMHmacSharingParameters inst = repository.newHmacSharingParameters();
    inst.vals = KMArray.instance((short) 2);
    inst.vals.add(SEED, KMByteBlob.instance());
    inst.vals.add(NONCE, KMByteBlob.instance());
    return inst;
  }

  public static KMHmacSharingParameters instance(KMArray vals) {
    if (vals.length() != 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    KMHmacSharingParameters inst = repository.newHmacSharingParameters();
    inst.vals = vals;
    return inst;
  }

  public static void create(KMHmacSharingParameters[] hmacSharingParamsRefTable) {
    byte index = 0;
    while (index < hmacSharingParamsRefTable.length) {
      hmacSharingParamsRefTable[index] = new KMHmacSharingParameters();
      index++;
    }
  }

  public KMByteBlob getSeed() {
    return (KMByteBlob) vals.get(SEED);
  }

  public KMByteBlob getNonce() {
    return (KMByteBlob) vals.get(NONCE);
  }

  public KMArray getVals() {
    return vals;
  }
}
