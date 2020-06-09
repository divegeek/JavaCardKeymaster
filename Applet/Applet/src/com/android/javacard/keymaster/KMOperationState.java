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
  private boolean active;
  private boolean trustedConfirmation;
  // TODO This should be 64 bits
  private  short handle;
  private short purpose;
  private KMCipher cipher;
  private Signature hmacSigner; // used for trusted confirmation.
  private Signature signer;
  private byte[] key;
  private short keyLength;
  private byte[] authTime;
  private boolean authPerOperationReqd;
  private boolean authTimeoutValidated;

  public KMOperationState(){
    authTime = new byte[8];
    key = new byte[256];
    reset();
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
    keyLength = 0;
    authPerOperationReqd = false;
    active = false;
    handle = 0;
    key = null;
    cipher = null;
    signer = null;
    purpose = KMType.INVALID_VALUE;
    trustedConfirmation = false;
    hmacSigner = null;
    authTimeoutValidated = false;
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

  public short getHandle() {
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

  public Signature getSigner() {
    return signer;
  }

  public void setSigner(Signature signer) {
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

  public boolean isAuthPerOperation() {
    return authPerOperationReqd;
  }

  public boolean isAuthTimeoutValidated() {
    return authTimeoutValidated;
  }

  public byte[] getAuthTime() {
    return authTime;
  }

  public void setAuthTime(byte[] time, short start) {
    Util.arrayCopy(time, start, authTime, (short)0, (short)8);
  }

  public void setAuthTimeoutValidated(boolean flag) {
    authTimeoutValidated = flag;
  }
}
