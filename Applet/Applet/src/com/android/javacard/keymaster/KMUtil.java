package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class KMUtil {
  public static final byte AES_BLOCK_SIZE = 16;
  private static KMRepository repository = null;
  private static byte[] counter;
  private static boolean initialized = false;
  private static AESKey aesKey;
  private static Cipher aesEcb;

  public static void init(KMRepository repo) {
    if (!initialized) {
      KMUtil.repository = repo;
      counter = repo.newIntegerArray((short) 8);
      KMUtil.initEntropyPool(repo.getEntropyPool());
      try {
        aesEcb = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
      } catch (CryptoException exp) {
        // TODO change this to proper error code
        throw new KMException(ISO7816.SW_UNKNOWN);
      }
      aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
      initialized = true;
    }
  }

  public static void initEntropyPool(byte[] pool) {
    byte index = 0;
    RandomData trng;
    while (index < counter.length) {
      counter[index++] = 0;
    }
    try {
      trng = RandomData.getInstance(RandomData.ALG_TRNG);
    } catch (CryptoException exp) {
      if (exp.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
        //TODO change this when possible
        // simulator does not support TRNG algorithm. So, PRNG algorithm (deprecated) is used.
        trng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
      } else {
        // TODO change this to proper error code
        throw new KMException(ISO7816.SW_UNKNOWN);
      }
    }
    trng.nextBytes(pool, (short) 0, (short) pool.length);
  }

  // Generate a secure random number from existing entropy pool. This uses aes ecb algorithm with
  // 8 byte counter and 16 byte block size.
  public static void newRandomNumber(byte[] num, short startOff, short length) {
    byte[] bufPtr = repository.getByteHeapRef();
    short countBufInd = repository.newByteArray(AES_BLOCK_SIZE);
    short randBufInd = repository.newByteArray(AES_BLOCK_SIZE);
    short len = AES_BLOCK_SIZE;
    while (length > 0) {
      if (length < len ) len = length;
      // increment counter by one
      incrementCounter();
      // copy the 8 byte counter into the 16 byte counter buffer.
      Util.arrayCopy(counter, (short) 0, bufPtr, countBufInd, (short) counter.length);
      // encrypt the counter buffer with existing entropy which forms the aes key.
      aesKey.setKey(repository.getEntropyPool(), (short) 0);
      aesEcb.init(aesKey, Cipher.MODE_ENCRYPT);
      aesEcb.doFinal(bufPtr, countBufInd, AES_BLOCK_SIZE, bufPtr, randBufInd);
      // copy the encrypted counter block to buffer passed in the argument
      Util.arrayCopy(bufPtr, randBufInd, num, startOff, len);
      length = (short) (length - len);
      startOff = (short)(startOff + len);
    }
  }

  // increment 8 byte counter by one
  private static void incrementCounter() {
    // start with least significant byte
    short index = (short) (counter.length - 1);
    while (index >= 0) {
      // if the msb of current byte is set then it will be negative
      if (counter[index] < 0) {
        // then increment the counter
        counter[index]++;
        // is the msb still set? i.e. no carry over
        if (counter[index] < 0) break; // then break
        else index--; // else go to the higher order byte
      } else {
        // if msb is not set then increment the counter
        counter[index]++;
        // is the msb still not set i.e. no carry over
        if (counter[index] >= 0) break; // then break
        else index--; // else go to the higher order byte
      }
    }
  }
}
