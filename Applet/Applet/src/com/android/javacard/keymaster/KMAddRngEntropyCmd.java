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

import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;

// This command adds entropy into the current entropy pool as per hal specifications.
public class KMAddRngEntropyCmd extends KMAbstractCmd {
  public static final byte INS_ADD_RNG_ENTROPY_CMD = 0x18;
  public static final short MAX_SEED_SIZE = 2048;

  @Override
  protected KMArray getExpectedArgs() {
    return KMArray.instance((short) 1).add((short) 0, KMByteBlob.instance());
  }

  @Override
  protected KMArray process(KMArray args, KMContext context) {
    KMByteBlob blob = (KMByteBlob) args.get((short) 0);
    // maximum 2KiB of seed is allowed.
    if (blob.length() > MAX_SEED_SIZE) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    KMUtil.init(context.getRepository());
    // Get existing entropy pool.
    byte[] entPool = context.getRepository().getEntropyPool();
    // Create new temporary pool.
    byte[] heapRef = context.getRepository().getByteHeapRef();
    short poolStart = context.getRepository().newByteArray((short) entPool.length);
    // Populate the new pool with the entropy which is derived from current entropy pool.
    KMUtil.newRandomNumber(heapRef, poolStart, (short) entPool.length);
    // Copy the entropy to the current pool - updates the entropy pool.
    Util.arrayCopy(heapRef, poolStart, entPool, (short) 0, (short) entPool.length);
    short index = 0;
    short randIndex = 0;
    // Mix (XOR) the seed received from the master in the entropy pool - 32 bytes (entPool.length).
    // at a time.
    while (index < blob.length()) {
      entPool[randIndex] = (byte) (entPool[randIndex] ^ blob.get(index));
      randIndex++;
      index++;
      if (randIndex >= entPool.length) {
        randIndex = 0;
      }
    }
    // TODO return success error code.
    return null;
  }

  @Override
  public byte getIns() {
    return INS_ADD_RNG_ENTROPY_CMD;
  }
}
