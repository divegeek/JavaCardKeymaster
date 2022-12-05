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
 * KMError includes all the error codes from android keymaster hal specifications. The values are
 * positive unlike negative values in keymaster hal.
 */
public class KMError {

  public static final short OK = 0;
  public static final short UNSUPPORTED_PURPOSE = 2;
  public static final short UNSUPPORTED_ALGORITHM = 4;
  public static final short INVALID_INPUT_LENGTH = 21;
  public static final short VERIFICATION_FAILED = 30;
  public static final short TOO_MANY_OPERATIONS = 31;
  public static final short INVALID_ARGUMENT = 38;
  public static final short UNKNOWN_ERROR = 1000;
}
