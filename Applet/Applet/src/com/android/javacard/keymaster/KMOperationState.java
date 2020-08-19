/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.Signature;

// TODO complete the class design and implementation
public class KMOperationState {
  private short opHandleCounter;
  private byte algorithm;
  private byte padding;
  private byte blockMode;
  private byte digest;
  private short purpose;
  private short keySize;
  private boolean active;
  private boolean trustedConfirmation;
  private boolean cipherOperation;
  // TODO This should be 64 bits
  private  short handle;
  private KMCipher cipher;
  private Signature hmacSigner; // used for trusted confirmation.
  private Signature signer;
  private byte[] key;
  private short keyLength;
  private byte[] authTime;
  private boolean authPerOperationReqd;
  private boolean secureUserIdReqd;
  private boolean authTimeoutValidated;
  private boolean aesGcmUpdateAllowed;

  private boolean aesBlockSaved;
  private byte[] aesBlock;
  private short macLength;

  public KMOperationState(){
    authTime = new byte[8];
    key = new byte[256];
    aesBlock = new byte[KMKeymasterApplet.AES_BLOCK_SIZE];
    reset();
  }

  public short getKeySize() {
    return keySize;
  }

  public void setKeySize(short keySize) {
    this.keySize = keySize;
  }


  public void setTrustedConfirmationSigner(Signature hmacSigner){
    this.hmacSigner = hmacSigner;
    trustedConfirmation = true;
  }
  public Signature getTrustedConfirmationSigner(){
    return hmacSigner;
  }
  public boolean isTrustedConfirmationRequired(){
    return trustedConfirmation;
  }
  public void activate(){
    active = true;
    handle = getOpHandleCounter();
  }
  public void reset(){
    Util.arrayFillNonAtomic(authTime, (short)0,(short)8, (byte)0);
    cipherOperation = false;
    keyLength = 0;
    authPerOperationReqd = false;
    secureUserIdReqd = false;
    active = false;
    handle = 0;
    Util.arrayFillNonAtomic(key,(short)0,(short)key.length,(byte)0);
    cipher = null;
    signer = null;
    purpose = KMType.INVALID_VALUE;
    trustedConfirmation = false;
    hmacSigner = null;
    authTimeoutValidated = false;
    aesGcmUpdateAllowed = false;
    aesBlockSaved = false;
    macLength = 0;
  }
  //TODO make this random number
  public short getOpHandleCounter() {
    opHandleCounter++;
    if(opHandleCounter < 0){
      opHandleCounter = 0;
    }
    return opHandleCounter;
  }

  public boolean isActive() {
    return active;
  }
  public boolean isCipherOperation(){ return cipherOperation;}
  public void setCipherOperation(boolean flag){cipherOperation = flag;}

  public short getHandle() {
    return KMInteger.uint_16(handle);
  }

  public short handle(){
    return handle;
  }
  public short getPurpose() {
    return purpose;
  }

  public void setPurpose(short purpose) {
    this.purpose = purpose;
  }

  public KMCipher getCipher() {
    return cipher;
  }

  public void setCipher(KMCipher cipher) {
    this.cipher = cipher;
  }

  public Signature getSignerVerifier() {
    return signer;
  }

  public void setSignerVerifier(Signature signer) {
    this.signer = signer;
  }

  public short getKey(byte[] buf, short start) {
    Util.arrayCopy(key,(short)0, buf, start,keyLength);
    return keyLength;
  }

  public void setKey(byte[] buf, short start, short len) {
    keyLength = len;
    Util.arrayCopy(buf, start, key, (short)0, len);
  }

  public boolean isAuthPerOperationReqd() {
    return authPerOperationReqd;
  }

  public boolean isAuthTimeoutValidated() {
    return authTimeoutValidated;
  }
  public boolean isSecureUserIdReqd(){return secureUserIdReqd;}

  public byte[] getAuthTime() {
    return authTime;
  }

  public void setAuthTime(byte[] time, short start) {
    Util.arrayCopy(time, start, authTime, (short)0, (short)8);
  }
  public void setOneTimeAuthReqd(boolean flag){secureUserIdReqd = flag;}
  public void setAuthTimeoutValidated(boolean flag) {
    authTimeoutValidated = flag;
  }
  public void setAuthPerOperationReqd(boolean flag){ authPerOperationReqd = flag;}

  public byte getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(byte algorithm) {
    this.algorithm = algorithm;
  }

  public byte getPadding() {
    return padding;
  }

  public void setPadding(byte padding) {
    this.padding = padding;
  }

  public byte getBlockMode() {
    return blockMode;
  }

  public void setBlockMode(byte blockMode) {
    this.blockMode = blockMode;
  }

  public byte getDigest() {
    return digest;
  }

  public void setDigest(byte digest) {
    this.digest = digest;
  }

  public boolean isAesGcmUpdateAllowed(){
    return aesGcmUpdateAllowed;
  }
  public void setAesGcmUpdateComplete(){
    aesGcmUpdateAllowed = false;
  }
  public void setAesGcmUpdateStart(){
    aesGcmUpdateAllowed = true;
  }
  public byte[] getAesBlock(){
    return aesBlock;
  }

  public void setAesBlock(byte[] buf, short start, short length){
    if(aesBlock.length != length) KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    Util.arrayCopy(buf,start,aesBlock, (short)0, length);
    aesBlockSaved = true;
  }

  public boolean isAesBlockSaved() {
    return aesBlockSaved;
  }

  public void setMacLength(short length) {
    macLength = length;
  }

  public short getMacLength() {
    return macLength;
  }
}
