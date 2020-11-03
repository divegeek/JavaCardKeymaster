package com.android.javacard.keymaster;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

public class KMBackupStoreApplet extends Applet implements KMBackupRestoreAgent {
  private static final short DATA_TABLE_MEM_SIZE = 2048;
  private static final byte[] aidArr = new byte[]{ (byte)0xA0, 0x00, 0x00, 0x00, 0x62};

  private byte[] dataTable;
  private short dataTableSize;

  private KMBackupStoreApplet() {
    dataTable = new byte[DATA_TABLE_MEM_SIZE];
  }

  public static void install(byte bArray[], short bOffset, byte bLength) {
    new KMBackupStoreApplet().register();
  }

  @Override
  public boolean select() {
    return true;
  }

  @Override
  public void process(APDU apdu) {

  }

  @Override
  public void backup(byte[] buf, short start, short len) {
    // Store the data
    if (len > 0) {
      JCSystem.beginTransaction();
      dataTableSize = len;
      Util.arrayCopy(buf, start, dataTable, (short) 0, len);
      JCSystem.commitTransaction();
    }
  }

  @Override
  public short restore(byte[] buf, short start) {
    // Restore the data
    Util.arrayCopy(dataTable, (short) 0, buf, start, dataTableSize);
    return dataTableSize;
  }

  @Override
  public Shareable getShareableInterfaceObject(AID aid, byte param){
    byte[] aidBytes = new byte[10];
    byte len = aid.getBytes(aidBytes, (short)0);
    if(Util.arrayCompare(aidArr,(short)0,aidBytes,(short)0,len) == 0){
      return this;
    }
    return null;
  }

}
