
package com.android.javacard.keymaster;

public class KMSEProviderImpl {
  public static KMSEProvider instance(){
    return new KMSimulator();
  }
}
