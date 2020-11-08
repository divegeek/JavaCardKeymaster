package com.android.javacard.keymaster;

import javacard.framework.Shareable;

public interface KMBackupRestoreAgent extends Shareable {
  void backup(byte[] buf, short start, short len);
  short restore(byte[] buf, short start);
  void backupProviderData(byte[] buf, short start, short len);
  short restoreProviderData(byte[] buf, short start);
  boolean isBackupAvailable();
}
