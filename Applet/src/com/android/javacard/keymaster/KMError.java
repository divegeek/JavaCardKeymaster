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

/**
 * KMError includes all the error codes from android keymaster hal specifications. The values are
 * positive unlike negative values in keymaster hal.
 */
public class KMError {

  public static final short OK = 0;
  public static final short UNSUPPORTED_PURPOSE = 2;
  public static final short INCOMPATIBLE_PURPOSE = 3;
  public static final short UNSUPPORTED_ALGORITHM = 4;
  public static final short INCOMPATIBLE_ALGORITHM = 5;
  public static final short UNSUPPORTED_KEY_SIZE = 6;
  public static final short UNSUPPORTED_BLOCK_MODE = 7;
  public static final short INCOMPATIBLE_BLOCK_MODE = 8;
  public static final short UNSUPPORTED_MAC_LENGTH = 9;
  public static final short UNSUPPORTED_PADDING_MODE = 10;
  public static final short INCOMPATIBLE_PADDING_MODE = 11;
  public static final short UNSUPPORTED_DIGEST = 12;
  public static final short INCOMPATIBLE_DIGEST = 13;

  public static final short UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = 19;

  /**
   * For PKCS8 & PKCS12
   */
  public static final short INVALID_INPUT_LENGTH = 21;


  public static final short KEY_USER_NOT_AUTHENTICATED = 26;
  public static final short INVALID_OPERATION_HANDLE = 28;
  public static final short VERIFICATION_FAILED = 30;
  public static final short TOO_MANY_OPERATIONS = 31;
  public static final short INVALID_KEY_BLOB = 33;

  public static final short INVALID_ARGUMENT = 38;
  public static final short UNSUPPORTED_TAG = 39;
  public static final short INVALID_TAG = 40;
  public static final short IMPORT_PARAMETER_MISMATCH = 44;
  public static final short OPERATION_CANCELLED = 46;

  public static final short MISSING_NONCE = 51;
  public static final short INVALID_NONCE = 52;
  public static final short MISSING_MAC_LENGTH = 53;
  public static final short CALLER_NONCE_PROHIBITED = 55;
  public static final short INVALID_MAC_LENGTH = 57;
  public static final short MISSING_MIN_MAC_LENGTH = 58;
  public static final short UNSUPPORTED_MIN_MAC_LENGTH = 59;
  public static final short UNSUPPORTED_EC_CURVE = 61;
  public static final short KEY_REQUIRES_UPGRADE = 62;

  public static final short ATTESTATION_APPLICATION_ID_MISSING = 65;
  public static final short CANNOT_ATTEST_IDS = 66;
  public static final short ROLLBACK_RESISTANCE_UNAVAILABLE = 67;

  public static final short DEVICE_LOCKED = 72;
  public static final short EARLY_BOOT_ENDED = 73;
  public static final short UNIMPLEMENTED = 100;
  public static final short UNKNOWN_ERROR = 1000;

  //Extended errors
  public static final short SW_CONDITIONS_NOT_SATISFIED = 10001;
  public static final short UNSUPPORTED_CLA = 10002;
  public static final short INVALID_P1P2 = 10003;
  public static final short UNSUPPORTED_INSTRUCTION = 10004;
  public static final short CMD_NOT_ALLOWED = 10005;
  public static final short SW_WRONG_LENGTH = 10006;
  public static final short INVALID_DATA = 10007;
  //Crypto errors
  public static final short CRYPTO_ILLEGAL_USE = 10008;
  public static final short CRYPTO_ILLEGAL_VALUE = 10009;
  public static final short CRYPTO_INVALID_INIT = 10010;
  public static final short CRYPTO_NO_SUCH_ALGORITHM = 10011;
  public static final short CRYPTO_UNINITIALIZED_KEY = 10012;
  //Generic Unknown error.
  public static final short GENERIC_UNKNOWN_ERROR = 10013;

}
