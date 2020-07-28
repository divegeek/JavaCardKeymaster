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

public class KMException extends RuntimeException {
  public static short reason;
  public static KMException exception;
  private KMException(){
  }
  public static void throwIt(short reason){
    KMException.reason = reason;
    throw instance();
  }
  public static KMException instance(){
    if(exception == null ) exception = new KMException();
    return exception;
  }

  public void clear(){
    reason = KMError.UNKNOWN_ERROR;
  }
}


