
package com.android.javacard.keymaster;

public class KMSEProviderImpl {
  public static KMSEProvider instance(boolean isUpgrading){
    return new AndroidSEProvider(isUpgrading);
  }
}
