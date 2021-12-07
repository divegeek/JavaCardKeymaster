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

public interface KMPKCS8Decoder {

  /**
   * Decodes the PKCS8 encoded RSA Key and extracts the private and public key
   *
   * @param Instance of the PKCS8 encoded data
   * @return Instance of KMArray holding RSA public key, RSA private key and modulus.
   */
  short decodeRsa(short blob);

  /**
   * Decodes the PKCS8 encoded EC Key and extracts the private and public key
   *
   * @param Instance of the PKCS8 encoded data.
   * @return Instance of KMArray holding EC public key and EC private key.
   */
  short decodeEc(short blob);

}
