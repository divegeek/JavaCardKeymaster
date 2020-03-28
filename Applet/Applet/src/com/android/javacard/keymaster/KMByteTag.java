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

public class KMByteTag extends KMTag {

  private static final short[] tags = {
    APPLICATION_ID,
    APPLICATION_DATA,
    ROOT_OF_TRUST,
    UNIQUE_ID,
    ATTESTATION_CHALLENGE,
    ATTESTATION_APPLICATION_ID,
    ATTESTATION_ID_BRAND,
    ATTESTATION_ID_DEVICE,
    ATTESTATION_ID_PRODUCT,
    ATTESTATION_ID_SERIAL,
    ATTESTATION_ID_IMEI,
    ATTESTATION_ID_MEID,
    ATTESTATION_ID_MANUFACTURER,
    ATTESTATION_ID_MODEL,
    ASSOCIATED_DATA,
    NONCE,
    CONFIRMATION_TOKEN
  };

  private short key;
  private KMByteBlob val;

  private KMByteTag() {
    init();
  }

  @Override
  public void init() {
    key = 0;
    val = null;
  }

  @Override
  public short getKey() {
    return key;
  }

  @Override
  public short length() {
    return val.length();
  }

  @Override
  public short getTagType() {
    return KMType.BYTES_TAG;
  }

  public static KMByteTag instance() {
    return repository.newByteTag();
  }

  public static KMByteTag instance(short key) {
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    KMByteTag tag = repository.newByteTag();
    tag.key = key;
    tag.val = null;
    return tag;
  }

  public static void create(KMByteTag[] byteTagRefTable) {
    byte index = 0;
    while (index < byteTagRefTable.length) {
      byteTagRefTable[index] = new KMByteTag();
      index++;
    }
  }

  // create default assignBlob without any value
  public static KMByteTag instance(short key, KMByteBlob array) {
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    KMByteTag tag = repository.newByteTag();
    tag.key = key;
    tag.val = array;
    return tag;
  }

  public KMByteTag withLength(short length) {
    this.val.withLength(length);
    return this;
  }

  private static boolean validateKey(short key) {
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        return true;
      }
    }
    return false;
  }

  public KMByteBlob getValue() {
    return val;
  }

  public KMByteTag setValue(KMByteBlob val) {
    this.val = val;
    return this;
  }
}
