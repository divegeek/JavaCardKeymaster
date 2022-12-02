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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.keymaster;

/**
 * This class constructs the Cose messages like CoseKey, CoseMac0, MacStructure,
 * CoseSign1, SignStructure, CoseEncrypt, EncryptStructure and ReceipientStructures.
 */
public class KMCose {
  //COSE MAC0
  public static final short COSE_MAC0_ENTRY_COUNT = 4;
  public static final short COSE_MAC0_PROTECTED_PARAMS_OFFSET = 0;
  public static final short COSE_MAC0_UNPROTECTED_PARAMS_OFFSET = 1;
  public static final short COSE_MAC0_PAYLOAD_OFFSET = 2;
  public static final short COSE_MAC0_TAG_OFFSET = 3;
  //COSE Labels
  public static final byte COSE_LABEL_ALGORITHM = 1;
  //COSE Algorithms
  public static final byte COSE_ALG_HMAC_256 = 5; //HMAC w/ SHA-256
  //Context strings
  public static final byte[] MAC_CONTEXT = {0x4d, 0x41, 0x43, 0x30}; // MAC0

  /**
   * Constructs the Cose MAC structure.
   *
   * @param protectedHeader Bstr pointer which holds the protected header.
   * @param extAad          Bstr pointer which holds the external Aad.
   * @param payload         Bstr pointer which holds the payload of the MAC structure.
   * @return KMArray instance of MAC structure.
   */
  public static short constructCoseMacStructure(short protectedHeader, short extAad, short payload) {
    // Create MAC Structure and compute HMAC as per https://tools.ietf.org/html/rfc8152#section-6.3
    //    MAC_structure = [
    //        context : "MAC" / "MAC0",
    //        protected : empty_or_serialized_map,
    //        external_aad : bstr,
    //        payload : bstr
    //   ]
    short arrPtr = KMArray.instance(KMCose.COSE_MAC0_ENTRY_COUNT);
    // 1 - Context
    KMArray.cast(arrPtr).add((short) 0, KMTextString.instance(KMCose.MAC_CONTEXT, (short) 0,
        (short) KMCose.MAC_CONTEXT.length));
    // 2 - Protected headers.
    KMArray.cast(arrPtr).add((short) 1, protectedHeader);
    // 3 - external aad
    KMArray.cast(arrPtr).add((short) 2, extAad);
    // 4 - payload.
    KMArray.cast(arrPtr).add((short) 3, payload);
    return arrPtr;
  }

  /**
   * Constructs the COSE_MAC0 object.
   *
   * @param protectedHeader   Bstr pointer which holds the protected header.
   * @param unprotectedHeader Bstr pointer which holds the unprotected header.
   * @param payload           Bstr pointer which holds the payload of the MAC structure.
   * @param tag               Bstr pointer which holds the tag value.
   * @return KMArray instance of COSE_MAC0 object.
   */
  public static short constructCoseMac0(short protectedHeader, short unprotectedHeader, short payload, short tag) {
    // Construct Cose_MAC0
    //   COSE_Mac0 = [
    //      protectedHeader,
    //      unprotectedHeader,
    //      payload : bstr / nil,
    //      tag : bstr,
    //   ]
    short arrPtr = KMArray.instance(KMCose.COSE_MAC0_ENTRY_COUNT);
    // 1 - protected headers
    KMArray.cast(arrPtr).add((short) 0, protectedHeader);
    // 2 - unprotected headers
    KMArray.cast(arrPtr).add((short) 1, unprotectedHeader);
    // 2 - payload
    KMArray.cast(arrPtr).add((short) 2, payload);
    // 3 - tag
    KMArray.cast(arrPtr).add((short) 3, tag);
    // Do encode.
    return arrPtr;
  }

}
