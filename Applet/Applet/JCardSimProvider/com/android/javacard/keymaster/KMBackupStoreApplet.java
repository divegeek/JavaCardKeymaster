package com.android.javacard.keymaster;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

public class KMBackupStoreApplet extends Applet implements KMBackupRestoreAgent {
  private static final short PROVIDER_MEM_SIZE = 2050;
  private static final short KM_APPLET_MEM_SIZE = 2050;
  private static final short PROVIDER_OFFSET = 0;
  private static final short KM_APPLET_DATA_OFFSET = PROVIDER_MEM_SIZE;
  private static final byte[] aidArr = new byte[]{ (byte)0xA0, 0x00, 0x00, 0x00, 0x62};

  private byte[] dataTable;
  boolean backupAvailable;

  private KMBackupStoreApplet() {
    dataTable = new byte[KM_APPLET_MEM_SIZE + PROVIDER_MEM_SIZE];
    backupAvailable = false;
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
      // dataTableSize = len;
      Util.setShort(dataTable, KM_APPLET_DATA_OFFSET, len);
      Util.arrayCopy(buf, start, dataTable,
          (short) (KM_APPLET_DATA_OFFSET + 2), len);
      JCSystem.commitTransaction();
    }
    backupAvailable = true;
  }

  @Override
  public short restore(byte[] buf, short start) {
    // Restore the data
    short len = Util.getShort(dataTable, KM_APPLET_DATA_OFFSET);
    Util.arrayCopyNonAtomic(dataTable, (short) (KM_APPLET_DATA_OFFSET + 2), buf, start,
        len);
    return len;
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

  @Override
  public boolean isBackupAvailable() {
    return backupAvailable;
  }

  @Override
  public void backupProviderData(byte[] buf, short start, short len) {
    // Store the data
    if (len > 0) {
      JCSystem.beginTransaction();
      Util.arrayCopy(buf, start, dataTable, PROVIDER_OFFSET, len);
      JCSystem.commitTransaction();
    }
    backupAvailable = true;
  }

  @Override
  public short restoreProviderData(byte[] buf, short start) {
    // Restore the data
    short len = Util.getShort(dataTable, PROVIDER_OFFSET);
    len += 2;// including length.
    Util.arrayCopyNonAtomic(dataTable, PROVIDER_OFFSET, buf, start, len);
    return len;
  }

}
