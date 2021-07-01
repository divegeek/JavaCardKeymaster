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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import javacard.security.AESKey;

public class KMAESKey implements KMMasterKey {

  private AESKey aesKey;

  public KMAESKey(AESKey key) {
    aesKey = key;
  }

  public void setKey(byte[] keyData, short kOff) {
    aesKey.setKey(keyData, kOff);
  }

  public byte getKey(byte[] keyData, short kOff) {
    return aesKey.getKey(keyData, kOff);
  }

  public short getKeySizeBits() {
    return aesKey.getSize();
  }
}
