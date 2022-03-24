/*
 * Copyright(C) 2021 The Android Open Source Project
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
package com.android.javacard.seprovider;
import org.globalplatform.upgrade.Element;

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

public class KMECDeviceUniqueKey implements KMDeviceUniqueKeyPair {

  private KeyPair ecKeyPair;

  @Override
  public short getPublicKey(byte[] buf, short offset) {
    ECPublicKey publicKey = getPublicKey();
    return publicKey.getW(buf, offset);
  }

  public KMECDeviceUniqueKey(KeyPair ecPair) {
    ecKeyPair = ecPair;
  }

  public void setS(byte[] buffer, short offset, short length) {
    ECPrivateKey ecPriv = (ECPrivateKey) ecKeyPair.getPrivate();
    ecPriv.setS(buffer, offset, length);
  }

  public void setW(byte[] buffer, short offset, short length) {
    ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
    ecPublicKey.setW(buffer, offset, length);
  }

  public ECPrivateKey getPrivateKey() {
    return (ECPrivateKey) ecKeyPair.getPrivate();
  }

  public ECPublicKey getPublicKey() {
    return (ECPublicKey) ecKeyPair.getPublic();
  }
  
  public static void onSave(Element element, KMECDeviceUniqueKey kmKey) {
    element.write(kmKey.ecKeyPair);
  }

  public static KMECDeviceUniqueKey onRestore(KeyPair ecKey) {
    if (ecKey == null) {
      return null;
    }
    return new KMECDeviceUniqueKey(ecKey);
  }

  public static short getBackupPrimitiveByteCount() {
    return (short) 0;
  }

  public static short getBackupObjectCount() {
    return (short) 1;
  }
}
