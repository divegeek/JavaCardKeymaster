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

import com.android.javacard.keymaster.KMPreSharedKey;

import javacard.security.HMACKey;

public class KMHmacKey implements KMPreSharedKey {

  private HMACKey hmacKey;

  public KMHmacKey(HMACKey key) {
    hmacKey = key;
  }

  public void setKey(byte[] keyData, short kOff, short length) {
    hmacKey.setKey(keyData, kOff, length);
  }

  public byte getKey(byte[] keyData, short kOff) {
    return hmacKey.getKey(keyData, kOff);
  }

  public short getKeySizeBits() {
    return hmacKey.getSize();
  }

  public static void onSave(Element element, KMHmacKey kmKey) {
    element.write(kmKey.hmacKey);
  }

  public static KMHmacKey onRestore(Element element) {
    HMACKey hmacKey = (HMACKey) element.readObject();
    KMHmacKey kmKey = new KMHmacKey(hmacKey);
    return kmKey;
  }

  public static short getBackupPrimitiveByteCount() {
    return (short) 0;
  }

  public static short getBackupObjectCount() {
    return (short) 1;
  }
}
