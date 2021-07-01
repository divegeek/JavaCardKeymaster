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

public abstract class KMCipher {

  public static final short SUN_JCE = 0xE9;

  public abstract short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad,
      short i);

  public abstract short update(byte[] buffer, short startOff, short length, byte[] scratchPad,
      short i);

  public abstract void updateAAD(byte[] buffer, short startOff, short length);

  public abstract short getBlockMode();

  public abstract void setBlockMode(short mode);

  public abstract short getPaddingAlgorithm();

  public abstract short getCipherAlgorithm();

  public abstract void setPaddingAlgorithm(short alg);

  public abstract void setCipherAlgorithm(short alg);

  public abstract short getCipherProvider();

  public abstract short getAesGcmOutputSize(short len, short macLength);
}
