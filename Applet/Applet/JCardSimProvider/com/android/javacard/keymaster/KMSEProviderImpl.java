
package com.android.javacard.keymaster;

public class KMSEProviderImpl {
  public static KMSEProvider instance(boolean isUpgrading) {
    //Ignore isUpgrading flag as JCardSimulator does not support upgrade.
    return new KMJcardSimulator();
  }
}
