package com.android.javacard.keymaster;

public class KMJCardSimApplet extends KMKeymasterApplet {

  KMJCardSimApplet(){
    super(new KMJCardSimulator());
  }
  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
      new KMJCardSimApplet().register();
  }

}
