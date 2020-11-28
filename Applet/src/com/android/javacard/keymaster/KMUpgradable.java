package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;

public interface KMUpgradable {
  void onSave(Element ele);
  
  void onRestore(Element ele);
  
  short getBackupPrimitiveByteCount();
  
  short getBackupObjectCount();

}
