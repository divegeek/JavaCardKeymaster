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
import javacard.framework.Util;

/**
 * KMByteTag represents BYTES Tag Type from android keymaster hal specifications. The tag value of this tag
 * is the KMByteBlob pointer i.e. offset of KMByteBlob in memory heap.
 * struct{byte TAG_TYPE; short length; struct{short BYTES_TAG; short tagKey; short blobPtr}}
 */

public class KMByteTag extends KMTag {
  private static KMByteTag prototype;
  private static short instPtr;

  // The allowed tag keys of type bool tag
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
    CONFIRMATION_TOKEN,
    VERIFIED_BOOT_KEY,
    VERIFIED_BOOT_HASH
  };

  private KMByteTag() {}

  private static KMByteTag proto(short ptr) {
    if (prototype == null) prototype = new KMByteTag();
    instPtr = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short blobPtr = KMByteBlob.exp();
    short ptr = instance(TAG_TYPE, (short)6);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), BYTES_TAG);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+2), INVALID_TAG);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+4), blobPtr);
    return ptr;
  }

  public static short instance(short key) {
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    return instance(key, KMByteBlob.exp());
  }

  public static short instance(short key, short byteBlob) {
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if(heap[byteBlob] != BYTE_BLOB_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = instance(TAG_TYPE, (short)6);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), BYTES_TAG);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+2), key);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+4), byteBlob);
    return ptr;
  }

  public static KMByteTag cast(short ptr) {
    if (heap[ptr] != TAG_TYPE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    if (Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE)) != BYTES_TAG) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getKey() {
    return Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE+2));
  }

  public short getTagType() {
    return KMType.BYTES_TAG;
  }

  public short getValue() {
    return Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE+4));
  }

  public short length() {
    short blobPtr = Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE+4));
    return KMByteBlob.cast(blobPtr).length();
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
}
