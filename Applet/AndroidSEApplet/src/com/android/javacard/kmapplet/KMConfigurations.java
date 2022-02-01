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
package com.android.javacard.kmapplet;

public class KMConfigurations {

  // Machine types
  public static final byte LITTLE_ENDIAN = 0x00;
  public static final byte BIG_ENDIAN = 0x01;
  public static final byte TEE_MACHINE_TYPE = LITTLE_ENDIAN;

  // Maximum cert chain size
  public static final short CERT_CHAIN_MAX_SIZE = 2500;
  public static final short CERT_ISSUER_MAX_SIZE = 250;
  public static final short CERT_EXPIRY_MAX_SIZE = 20;
  public static final short TOTAL_ATTEST_IDS_SIZE = 300;
  public static final short ADDITIONAL_CERT_CHAIN_MAX_SIZE = 512;
  public static final short BOOT_CERT_CHAIN_MAX_SIZE = 512;
}
