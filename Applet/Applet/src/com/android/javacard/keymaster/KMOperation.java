package com.android.javacard.keymaster;

public interface KMOperation {
  short update(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
                        byte[] outputDataBuf, short outputDataStart);
  short update(byte[] inputDataBuf, short inputDataStart, short inputDataLength);
  short finish(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
                        byte[] outputDataBuf, short outputDataStart);
  short sign(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
             byte[] signBuf, short signStart);
  boolean verify(byte[] inputDataBuf, short inputDataStart, short inputDataLength,
                 byte[] signBuf, short signStart, short signLength);
  void abort();
  void updateAAD(byte[] dataBuf, short dataStart, short dataLength);

  short getAESGCMOutputSize(short dataSize, short macLength);
}
