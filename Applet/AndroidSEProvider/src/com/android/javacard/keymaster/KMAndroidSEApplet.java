package com.android.javacard.keymaster;

import org.globalplatform.upgrade.OnUpgradeListener;

public class KMAndroidSEApplet extends KMKeymasterApplet implements OnUpgradeListener {

    KMAndroidSEApplet(){
      super(new KMAndroidSEProvider(true));
    }
    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
      new KMAndroidSEApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }
  // TODO Move the onSave, onRestore, etc. methods from Keymaster Applet here.
  }

