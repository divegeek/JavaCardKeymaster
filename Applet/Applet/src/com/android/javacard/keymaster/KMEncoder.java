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

import javacard.framework.ISO7816;
import javacard.framework.Util;

public class KMEncoder {
  // major types
  private static final byte UINT_TYPE = 0x00;
  private static final byte BYTES_TYPE = 0x40;
  private static final byte ARRAY_TYPE = (byte) 0x80;
  private static final byte MAP_TYPE = (byte) 0xA0;

  // masks
  private static final byte ADDITIONAL_MASK = 0x1F;
  private static final byte MAJOR_TYPE_MASK = (byte) 0xE0;

  // value length
  private static final byte UINT8_LENGTH = (byte) 0x18;
  private static final byte UINT16_LENGTH = (byte) 0x19;
  private static final byte UINT32_LENGTH = (byte) 0x1A;
  private static final byte UINT64_LENGTH = (byte) 0x1B;
  private static final short TINY_PAYLOAD = 0x17;
  private static final short SHORT_PAYLOAD =  0x100;

  // TODO move the following to transient memory.
  private byte[] buffer;
  private short startOff;
  private short length;

  public KMEncoder() {
    buffer = null;
    startOff = 0;
    length = 0;
  }

  public short encode(KMArray object, byte[] buffer, short startOff, short length) {
    this.buffer = buffer;
    this.startOff = startOff;
    this.length = length;
    encode(object);
    this.length = this.startOff;
    this.startOff = startOff;
    return this.length;
  }

  private void encode(KMType exp){
    if(exp instanceof KMByteBlob){
      encode((KMByteBlob) exp);
      return;
    }
    if(exp instanceof KMEnum){
      encode((KMEnum) exp);
      return;
    }
    if(exp instanceof KMInteger){
      encode((KMInteger)exp);
      return;
    }
    if(exp instanceof KMArray){
      encode((KMArray)exp);
      return;
    }
    if(exp instanceof KMVector){
      encode((KMVector)exp);
      return;
    }
    if(exp instanceof KMByteTag){
      encode((KMByteTag)exp);
      return;
    }
    if(exp instanceof KMBoolTag){
      encode((KMBoolTag) exp);
      return;
    }
    if(exp instanceof KMIntegerTag){
      encode((KMIntegerTag)exp);
      return;
    }
    if(exp instanceof KMIntegerArrayTag){
      encode((KMIntegerArrayTag)exp);
      return;
    }
    if(exp instanceof KMEnumTag){
      encode((KMEnumTag) exp);
      return;
    }
    if(exp instanceof KMEnumArrayTag){
      encode((KMEnumArrayTag) exp);
      return;
    }
    if(exp instanceof KMKeyParameters){
      encode((KMKeyParameters) exp);
      return;
    }
    if(exp instanceof KMKeyCharacteristics){
      encode((KMKeyCharacteristics) exp);
      return;
    }
    if(exp instanceof KMVerificationToken){
      encode((KMVerificationToken) exp);
      return;
    }
    if(exp instanceof KMHmacSharingParameters){
      encode((KMHmacSharingParameters) exp);
      return;
    }
    if(exp instanceof KMHardwareAuthToken){
      encode((KMHardwareAuthToken) exp);
      return;
    }
    throw new KMException(ISO7816.SW_DATA_INVALID);
  }

  private void encode(KMKeyParameters obj) {
    encodeAsMap(obj.getVals());
  }
  private void encode(KMKeyCharacteristics obj) {
    encode(obj.getVals());
  }

  private void encode(KMVerificationToken obj) {
    encode(obj.getVals());
  }

  private void encode(KMHardwareAuthToken obj) {
    encode(obj.getVals());
  }

  private void encode(KMHmacSharingParameters obj) {
    encode(obj.getVals());
  }

  private void encode(KMArray obj) {
    writeMajorTypeWithLength(ARRAY_TYPE, obj.length());
    short index = 0;
    while(index < obj.length()){
      encode(obj.get(index));
      index++;
    }
  }

  private void encodeAsMap(KMArray obj){
    writeMajorTypeWithLength(MAP_TYPE, obj.length());
    short index = 0;
    while(index < obj.length()){
      KMType t = obj.get(index);
      encode(t);
      //encode(obj.get(index));
      index++;
    }
  }

  private void encode(KMVector obj){
    writeMajorTypeWithLength(ARRAY_TYPE, obj.length());
    short index = 0;
    while(index <obj.length()){
      encode(obj.getVals().get(index));
    }
  }
  private void encode(KMIntegerArrayTag obj) {
    writeTag(obj.getTagType(), obj.getKey());
    encode(obj.getValues());
  }

  private void encode(KMEnumArrayTag obj) {
    writeTag(obj.getTagType(), obj.getKey());
    encode(obj.getValues());
  }

  private void encode(KMIntegerTag obj) {
    writeTag(obj.getTagType(), obj.getKey());
    encode(obj.getValue());
  }

  private void encode(KMByteTag obj) {
    writeTag(obj.getTagType(), obj.getKey());
    encode(obj.getValue());
  }

  private void encode(KMBoolTag obj) {
    writeTag(obj.getTagType(), obj.getKey());
    writeByteValue(obj.getVal());
  }

  private void encode(KMEnumTag obj) {
    writeTag(obj.getTagType(), obj.getKey());
    writeByteValue(obj.getValue());
  }
  private void encode(KMEnum obj) {
    writeByteValue(obj.getVal());
  }

  private void encode(KMInteger obj) {
    byte[] val = obj.getValue();
    short len = obj.length();
    byte index =0;
    // find out the most significant byte
    while(index < len){
      if(val[index] > 0){
        break;
      }
      index++; // index will be equal to len if value is 0.
    }
    // find the difference between most significant byte and len
    short diff = (short)(len - index);
    if(diff == 0){
      writeByte((byte)(UINT_TYPE | 0));
    }else if((diff == 1) && val[index] < UINT8_LENGTH){
      writeByte((byte)(UINT_TYPE | val[index]));
    }else if (diff == 1){
      writeByte((byte)(UINT_TYPE | UINT8_LENGTH));
      writeByte(val[index]);
    }else if(diff == 2){
      writeByte((byte)(UINT_TYPE | UINT16_LENGTH));
      writeBytes(val, index, (short)2);
    }else if(diff <= 4){
      writeByte((byte)(UINT_TYPE | UINT32_LENGTH));
      writeBytes(val, (short)(len - 4), (short)4);
    }else {
      writeByte((byte)(UINT_TYPE | UINT64_LENGTH));
      writeBytes(val, (short)0, (short)8);
    }
  }

  private void encode(KMByteBlob obj) {
    writeMajorTypeWithLength(BYTES_TYPE, obj.length());
    writeBytes(obj.getVal(), obj.getStartOff(), obj.length());
  }

  private void writeByteValue(byte val){
    if(val < UINT8_LENGTH){
      writeByte((byte)(UINT_TYPE | val));
    }else{
      writeByte((byte)(UINT_TYPE | UINT8_LENGTH));
      writeByte(val);
    }
  }

  private void writeTag(short tagType, short tagKey){
    writeByte((byte)(UINT_TYPE | UINT32_LENGTH));
    writeShort(tagType);
    writeShort(tagKey);
  }
  // TODO bug here
  private void writeMajorTypeWithLength(byte majorType, short len) {
    if(len <= TINY_PAYLOAD){
      writeByte((byte)(majorType | (byte) (len & ADDITIONAL_MASK)));
    }else if(len < SHORT_PAYLOAD){
      writeByte((byte)(majorType | UINT8_LENGTH ));
      writeByte((byte)(len & 0xFF));
    }else {
      writeByte((byte)(majorType | UINT16_LENGTH ));
      writeShort(len);
    }
  }

  private void writeBytes(byte[] buf, short start, short len){
    Util.arrayCopy(buf, start, buffer, startOff, len);
    incrementStartOff(len);
  }
  private void writeShort(short val){
    buffer[startOff] = (byte)((val >> 8) & 0xFF);
    incrementStartOff((short)1);
    buffer[startOff] = (byte)((val & 0xFF));
    incrementStartOff((short)1);
  }
  private void writeByte(byte val){
    buffer[startOff] = val;
    incrementStartOff((short)1);
  }

  private void incrementStartOff(short inc){
    startOff += inc;
    if (startOff >= this.length) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
  }
}
