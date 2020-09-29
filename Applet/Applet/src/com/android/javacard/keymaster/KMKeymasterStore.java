package com.android.javacard.keymaster;

public interface KMKeymasterStore {
  short getMasterKeySecret(byte[] buf, short start);
  void createDocument(byte documentId, byte[]buf, short start, short len);
  void updateData(byte documentId, short keyId, byte[]buf, short start, short len);
  short getData(byte documentId, short keyId, byte[] buf, short start);
  short getDocument(byte documentId, byte[] buf, short start);
}
