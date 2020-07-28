package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class KMRng {
  public static final short ENTROPY_POOL_SIZE = 16; // simulator does not support 256 bit aes keys
  public static final byte[] aesICV = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  private static byte[] counter;
  private static AESKey aesKey;
  private static Cipher aesCbc;
  private static byte[] entropyPool;
  public static void init() {
      entropyPool = JCSystem.makeTransientByteArray(ENTROPY_POOL_SIZE, JCSystem.CLEAR_ON_RESET);
      counter = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
      KMRng.initEntropyPool(entropyPool);
      try {
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
      } catch (CryptoException exp) {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
      aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
  }

  public static void initEntropyPool(byte[] pool) {
    byte index = 0;
    RandomData trng;
    while (index < counter.length) {
      counter[index++] = 0;
    }
    try {
      trng = RandomData.getInstance(RandomData.ALG_TRNG);
      trng.nextBytes(pool, (short) 0, (short) pool.length);
    } catch (CryptoException exp) {
      if (exp.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
        //TODO change this when possible
        // simulator does not support TRNG algorithm. So, PRNG algorithm (deprecated) is used.
        trng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        trng.nextBytes(pool, (short) 0, (short) pool.length);
      } else {
        // TODO change this to proper error code
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
    }

  }

  // Generate a secure random number from existing entropy pool. This uses aes ecb algorithm with
  // 8 byte counter and 16 byte block size.
  public static void newRandomNumber(byte[] num, short startOff, short length) {
    KMRepository repository = KMRepository.instance();
    byte[] bufPtr = repository.getHeap();
    short countBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short randBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short len = KMKeymasterApplet.AES_BLOCK_SIZE;
    aesKey.setKey(entropyPool, (short) 0);
    aesCbc.init(aesKey, Cipher.MODE_ENCRYPT, aesICV, (short)0, (short)16);
    while (length > 0) {
      if (length < len ) len = length;
      // increment counter by one
      incrementCounter();
      // copy the 8 byte counter into the 16 byte counter buffer.
      Util.arrayCopy(counter, (short) 0, bufPtr, countBufInd, (short) counter.length);
      // encrypt the counter buffer with existing entropy which forms the aes key.
      aesCbc.doFinal(bufPtr, countBufInd, KMKeymasterApplet.AES_BLOCK_SIZE, bufPtr, randBufInd);
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
        break;
      }
    }
  }

  public static byte[] getEntropyPool() {
    return entropyPool;
  }

}
