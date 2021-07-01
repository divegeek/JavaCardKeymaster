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

import org.globalplatform.upgrade.Element;

import com.android.javacard.keymaster.KMMasterKey;

import javacard.security.AESKey;

public class KMAESKey implements KMMasterKey {

  private AESKey aesKey;

  public KMAESKey(AESKey key) {
    aesKey = key;
  }

  public void setKey(byte[] keyData, short kOff) {
    aesKey.setKey(keyData, kOff);
  }

  public AESKey getKey() {
    return aesKey;
  }

  public short getKeySizeBits() {
    return aesKey.getSize();
  }

  public static void onSave(Element element, KMAESKey kmKey) {
    element.write(kmKey.aesKey);
  }

  public static KMAESKey onRestore(Element element) {
    AESKey aesKey = (AESKey) element.readObject();
    KMAESKey kmKey = new KMAESKey(aesKey);
    return kmKey;
  }

  public static short getBackupPrimitiveByteCount() {
    return (short) 0;
  }

  public static short getBackupObjectCount() {
    return (short) 1;
  }

}
