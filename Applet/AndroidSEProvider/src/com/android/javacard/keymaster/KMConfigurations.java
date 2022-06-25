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

public class KMConfigurations {
  // Machine types
  public static final byte LITTLE_ENDIAN = 0x00;
  public static final byte BIG_ENDIAN = 0x01;
  public static final byte TEE_MACHINE_TYPE = LITTLE_ENDIAN;
  // If the size of the attestation ids is known and lesser than 64
  // then reduce the size here. It reduces the heap memory usage.
  public static final byte MAX_ATTESTATION_IDS_SIZE = 64;
  public static final short MAX_SUBJECT_DER_LEN = 1095;
}
