
package com.android.javacard.keymaster;

public class KMCryptoProviderImpl {
  public static KMCryptoProvider instance(){
    return new KMSimulator();
  }
}
