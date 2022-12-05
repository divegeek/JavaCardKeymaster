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

package com.android.javacard.seprovider;


/**
 * This class declares all types, tag types, and tag keys. It also establishes basic structure of
 * any KMType i.e. struct{byte type, short length, value} where value can any of the KMType. Also,
 * KMType refers to transient memory heap in the repository. Finally KMType's subtypes are singleton
 * prototype objects which just cast the structure over contiguous memory buffer.
 */
public abstract class KMType {

  public static final short INVALID_VALUE = (short) 0x8000;

  // Algorithm Enum Tag key and values
  public static final short ALGORITHM = 0x0002;
  public static final byte RSA = 0x01;
  public static final byte DES = 0x21;
  public static final byte EC = 0x03;
  public static final byte AES = 0x20;
  public static final byte HMAC = (byte) 0x80;

  // EcCurve Enum Tag key and values.
  public static final short ECCURVE = 0x000A;
  public static final byte P_224 = 0x00;
  public static final byte P_256 = 0x01;
  public static final byte P_384 = 0x02;
  public static final byte P_521 = 0x03;

  // Purpose
  public static final short PURPOSE = 0x0001;
  public static final byte ENCRYPT = 0x00;
  public static final byte DECRYPT = 0x01;
  public static final byte SIGN = 0x02;
  public static final byte VERIFY = 0x03;
  public static final byte DERIVE_KEY = 0x04;
  public static final byte WRAP_KEY = 0x05;
  public static final byte AGREE_KEY = 0x06;
  public static final byte ATTEST_KEY = (byte) 0x07;
  // Block mode
  public static final short BLOCK_MODE = 0x0004;
  public static final byte ECB = 0x01;
  public static final byte CBC = 0x02;
  public static final byte CTR = 0x03;
  public static final byte GCM = 0x20;

  // Digest
  public static final short DIGEST = 0x0005;
  public static final byte DIGEST_NONE = 0x00;
  public static final byte MD5 = 0x01;
  public static final byte SHA1 = 0x02;
  public static final byte SHA2_224 = 0x03;
  public static final byte SHA2_256 = 0x04;
  public static final byte SHA2_384 = 0x05;
  public static final byte SHA2_512 = 0x06;

  // Padding mode
  public static final short PADDING = 0x0006;
  public static final byte PADDING_NONE = 0x01;
  public static final byte RSA_OAEP = 0x02;
  public static final byte RSA_PSS = 0x03;
  public static final byte RSA_PKCS1_1_5_ENCRYPT = 0x04;
  public static final byte RSA_PKCS1_1_5_SIGN = 0x05;
  public static final byte PKCS7 = 0x40;

}
