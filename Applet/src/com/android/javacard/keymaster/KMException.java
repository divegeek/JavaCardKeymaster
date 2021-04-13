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

import javacard.framework.JCSystem;

/**
 * KMException is shared instance of exception used for all exceptions in the applet. It is used to
 * throw EMError errors.
 */
public class KMException extends RuntimeException {

  public short[] reason;
  public static KMException exception;

  private KMException() {
    reason = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
  }

  public static void throwIt(short reason) {
    instance();
    exception.reason[(short) 0] = reason;
    throw exception;
  }

  public static KMException instance() {
    if (exception == null) {
      exception = new KMException();
    }
    return exception;
  }

  public void clear() {
    exception.reason[(short) 0] = KMError.UNKNOWN_ERROR;
  }

  public static short getReason() {
    return exception.reason[0];
  }
}


