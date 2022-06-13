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

package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMAsn1Parser;
import com.android.javacard.keymaster.KMBoolTag;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMCose;
import com.android.javacard.keymaster.KMCoseHeaders;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMJCardSimApplet;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMNInteger;
import com.android.javacard.keymaster.KMRepository;
import com.android.javacard.keymaster.KMSimpleValue;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.seprovider.KMJCardSimulator;
import com.android.javacard.seprovider.KMSEProvider;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;

public class KMFunctionalTest {

  // Provider specific Commands
  private static final byte KEYMINT_CMD_APDU_START = 0x20;
  private static final byte INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1;  //0x21
  private static final byte INS_IMPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 2;    //0x22
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 3; //0x23
  private static final byte INS_EXPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 4; //0x24
  private static final byte INS_ATTEST_KEY_CMD = KEYMINT_CMD_APDU_START + 5; //0x25
  private static final byte INS_UPGRADE_KEY_CMD = KEYMINT_CMD_APDU_START + 6; //0x26
  private static final byte INS_DELETE_KEY_CMD = KEYMINT_CMD_APDU_START + 7; //0x27
  private static final byte INS_DELETE_ALL_KEYS_CMD = KEYMINT_CMD_APDU_START + 8; //0x28
  private static final byte INS_ADD_RNG_ENTROPY_CMD = KEYMINT_CMD_APDU_START + 9; //0x29
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = KEYMINT_CMD_APDU_START + 10; //0x2A
  private static final byte INS_DESTROY_ATT_IDS_CMD = KEYMINT_CMD_APDU_START + 11;  //0x2B
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = KEYMINT_CMD_APDU_START + 12; //0x2C
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = KEYMINT_CMD_APDU_START + 13; //0x2D
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = KEYMINT_CMD_APDU_START + 14; //0x2E
  private static final byte INS_GET_HW_INFO_CMD = KEYMINT_CMD_APDU_START + 15; //0x2F
  private static final byte INS_BEGIN_OPERATION_CMD = KEYMINT_CMD_APDU_START + 16;  //0x30
  private static final byte INS_UPDATE_OPERATION_CMD = KEYMINT_CMD_APDU_START + 17;  //0x31
  private static final byte INS_FINISH_OPERATION_CMD = KEYMINT_CMD_APDU_START + 18; //0x32
  private static final byte INS_ABORT_OPERATION_CMD = KEYMINT_CMD_APDU_START + 19; //0x33
  private static final byte INS_DEVICE_LOCKED_CMD = KEYMINT_CMD_APDU_START + 20;//0x34
  private static final byte INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21; //0x35
  private static final byte INS_GET_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 22; //0x36
  private static final byte INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23; //0x37
  private static final byte INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24; //0x38
  private static final byte INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25; //0x39
  private static final byte INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26; //0x3A
  // RKP
  public static final byte INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27; //0x3B
  public static final byte INS_GENERATE_RKP_KEY_CMD = KEYMINT_CMD_APDU_START + 28; //0x3C
  public static final byte INS_BEGIN_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 29; //0x3D
  public static final byte INS_UPDATE_KEY_CMD = KEYMINT_CMD_APDU_START + 30; //0x3E
  public static final byte INS_UPDATE_EEK_CHAIN_CMD = KEYMINT_CMD_APDU_START + 31; //0x3F
  public static final byte INS_UPDATE_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 32; //0x40
  public static final byte INS_FINISH_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 33; //0x41
  public static final byte INS_GET_RESPONSE_CMD = KEYMINT_CMD_APDU_START + 34; //0x42

  private static final byte KEYMINT_CMD_APDU_END = KEYMINT_CMD_APDU_START + 48; //0x50
  private static final byte INS_END_KM_CMD = 0x7F;
  private static final byte[] rsa_key_pkcs8 = {
      (byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0xbc, (byte) 0x02, (byte) 0x01, (byte) 0x00,
      (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
      (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05,
      (byte) 0x00, (byte) 0x04, (byte) 0x82, (byte) 0x04, (byte) 0xa6, (byte) 0x30, (byte) 0x82,
      (byte) 0x04, (byte) 0xa2, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x02, (byte) 0x82,
      (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0xc5, (byte) 0x28, (byte) 0x06, (byte) 0xb1,
      (byte) 0x75, (byte) 0x6c, (byte) 0x84, (byte) 0x7a, (byte) 0x61, (byte) 0x6e, (byte) 0x49,
      (byte) 0x66, (byte) 0xf8, (byte) 0x60, (byte) 0x4f, (byte) 0xec, (byte) 0x17, (byte) 0x8b,
      (byte) 0x34, (byte) 0xfc, (byte) 0x3f, (byte) 0xce, (byte) 0x70, (byte) 0x6a, (byte) 0x02,
      (byte) 0xf2, (byte) 0xf3, (byte) 0x6b, (byte) 0xb4, (byte) 0x78, (byte) 0xac, (byte) 0x8c,
      (byte) 0x7e, (byte) 0xc5, (byte) 0xf2, (byte) 0xa8, (byte) 0xea, (byte) 0xc1, (byte) 0xe5,
      (byte) 0xd3, (byte) 0xa8, (byte) 0xa9, (byte) 0x4b, (byte) 0x4b, (byte) 0x5a, (byte) 0x49,
      (byte) 0xc2, (byte) 0xe7, (byte) 0x85, (byte) 0xdf, (byte) 0x56, (byte) 0xa5, (byte) 0x34,
      (byte) 0xb2, (byte) 0xb6, (byte) 0xfd, (byte) 0xf2, (byte) 0xbc, (byte) 0xf1, (byte) 0xca,
      (byte) 0x34, (byte) 0xba, (byte) 0x60, (byte) 0x50, (byte) 0x8d, (byte) 0x0b, (byte) 0x61,
      (byte) 0xca, (byte) 0xd2, (byte) 0x76, (byte) 0x7d, (byte) 0xe4, (byte) 0xff, (byte) 0xdf,
      (byte) 0x39, (byte) 0x10, (byte) 0x68, (byte) 0x9c, (byte) 0x45, (byte) 0x79, (byte) 0x8c,
      (byte) 0x80, (byte) 0x0b, (byte) 0x58, (byte) 0xe4, (byte) 0x30, (byte) 0x9b, (byte) 0x74,
      (byte) 0xc5, (byte) 0x09, (byte) 0x5e, (byte) 0x16, (byte) 0xa1, (byte) 0x63, (byte) 0x7f,
      (byte) 0x03, (byte) 0xe9, (byte) 0xb0, (byte) 0x87, (byte) 0xf9, (byte) 0x81, (byte) 0x69,
      (byte) 0x35, (byte) 0xca, (byte) 0x86, (byte) 0xe6, (byte) 0xa2, (byte) 0x1d, (byte) 0x3f,
      (byte) 0xb8, (byte) 0x66, (byte) 0x39, (byte) 0x35, (byte) 0xf0, (byte) 0xef, (byte) 0xe3,
      (byte) 0xde, (byte) 0x11, (byte) 0xa9, (byte) 0x9d, (byte) 0x54, (byte) 0x6f, (byte) 0xa8,
      (byte) 0x04, (byte) 0x67, (byte) 0x75, (byte) 0x83, (byte) 0x67, (byte) 0xfb, (byte) 0xc2,
      (byte) 0x71, (byte) 0x25, (byte) 0x43, (byte) 0xbe, (byte) 0x9c, (byte) 0x8b, (byte) 0x3e,
      (byte) 0x94, (byte) 0x5e, (byte) 0xc1, (byte) 0x18, (byte) 0x83, (byte) 0x48, (byte) 0x9f,
      (byte) 0x4d, (byte) 0x09, (byte) 0x1c, (byte) 0x0c, (byte) 0x61, (byte) 0xc5, (byte) 0x50,
      (byte) 0x47, (byte) 0x34, (byte) 0x49, (byte) 0x17, (byte) 0x51, (byte) 0x16, (byte) 0xbc,
      (byte) 0x09, (byte) 0x9b, (byte) 0x14, (byte) 0xc9, (byte) 0x44, (byte) 0x68, (byte) 0x58,
      (byte) 0x19, (byte) 0xac, (byte) 0xf9, (byte) 0xd5, (byte) 0xa8, (byte) 0x52, (byte) 0x1f,
      (byte) 0xb2, (byte) 0xcc, (byte) 0x9a, (byte) 0x22, (byte) 0xfe, (byte) 0xa7, (byte) 0x76,
      (byte) 0x12, (byte) 0xe6, (byte) 0xfa, (byte) 0x3b, (byte) 0xc8, (byte) 0xe5, (byte) 0x26,
      (byte) 0x6f, (byte) 0x62, (byte) 0xd8, (byte) 0xa4, (byte) 0x20, (byte) 0x0a, (byte) 0x6b,
      (byte) 0x82, (byte) 0x6e, (byte) 0x43, (byte) 0x34, (byte) 0x34, (byte) 0x00, (byte) 0x59,
      (byte) 0xbb, (byte) 0x3e, (byte) 0x54, (byte) 0xc9, (byte) 0x35, (byte) 0x77, (byte) 0x14,
      (byte) 0xfd, (byte) 0x8b, (byte) 0xbd, (byte) 0x4e, (byte) 0xf0, (byte) 0x82, (byte) 0x6c,
      (byte) 0xd1, (byte) 0x3d, (byte) 0xc0, (byte) 0x65, (byte) 0x98, (byte) 0xe4, (byte) 0x7e,
      (byte) 0x4b, (byte) 0x69, (byte) 0xe0, (byte) 0x06, (byte) 0x92, (byte) 0x69, (byte) 0xb0,
      (byte) 0x77, (byte) 0x90, (byte) 0x6b, (byte) 0xaa, (byte) 0x48, (byte) 0x2b, (byte) 0xd5,
      (byte) 0x27, (byte) 0x95, (byte) 0xc2, (byte) 0xa6, (byte) 0x84, (byte) 0x45, (byte) 0xe2,
      (byte) 0x84, (byte) 0x18, (byte) 0x0f, (byte) 0xfe, (byte) 0xc5, (byte) 0xf9, (byte) 0xab,
      (byte) 0xbd, (byte) 0x28, (byte) 0x1d, (byte) 0x33, (byte) 0xcf, (byte) 0xb3, (byte) 0xb3,
      (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x82,
      (byte) 0x01, (byte) 0x00, (byte) 0x35, (byte) 0x96, (byte) 0x54, (byte) 0x83, (byte) 0x65,
      (byte) 0x6c, (byte) 0x32, (byte) 0x71, (byte) 0xe5, (byte) 0x0b, (byte) 0x89, (byte) 0xed,
      (byte) 0xef, (byte) 0xf2, (byte) 0x95, (byte) 0xa6, (byte) 0x91, (byte) 0x1b, (byte) 0xa8,
      (byte) 0x32, (byte) 0x2b, (byte) 0xd1, (byte) 0x9b, (byte) 0xa2, (byte) 0x64, (byte) 0xdc,
      (byte) 0xce, (byte) 0x26, (byte) 0xe7, (byte) 0x2d, (byte) 0xa9, (byte) 0x90, (byte) 0xa2,
      (byte) 0x60, (byte) 0x81, (byte) 0x3d, (byte) 0x42, (byte) 0x59, (byte) 0xa3, (byte) 0x73,
      (byte) 0x2d, (byte) 0x33, (byte) 0x9e, (byte) 0xa0, (byte) 0x83, (byte) 0x90, (byte) 0xea,
      (byte) 0xe5, (byte) 0xec, (byte) 0xf0, (byte) 0x30, (byte) 0x67, (byte) 0xc4, (byte) 0xf4,
      (byte) 0x12, (byte) 0x62, (byte) 0xe1, (byte) 0xd8, (byte) 0x53, (byte) 0x4b, (byte) 0xe7,
      (byte) 0x9b, (byte) 0x04, (byte) 0xd4, (byte) 0xc0, (byte) 0x11, (byte) 0x68, (byte) 0xea,
      (byte) 0x2c, (byte) 0xdc, (byte) 0x42, (byte) 0x09, (byte) 0xbd, (byte) 0x36, (byte) 0x5a,
      (byte) 0x17, (byte) 0x48, (byte) 0xa7, (byte) 0xb9, (byte) 0x06, (byte) 0x79, (byte) 0x96,
      (byte) 0xcf, (byte) 0xfe, (byte) 0xc0, (byte) 0x3f, (byte) 0x29, (byte) 0xf1, (byte) 0xca,
      (byte) 0x20, (byte) 0x6a, (byte) 0xaf, (byte) 0x71, (byte) 0xfc, (byte) 0x4e, (byte) 0x28,
      (byte) 0xad, (byte) 0x1a, (byte) 0xeb, (byte) 0x4a, (byte) 0x78, (byte) 0xcf, (byte) 0x34,
      (byte) 0xec, (byte) 0xb0, (byte) 0x4f, (byte) 0xfd, (byte) 0x9e, (byte) 0x3f, (byte) 0x94,
      (byte) 0x8a, (byte) 0x4c, (byte) 0x60, (byte) 0x89, (byte) 0xf5, (byte) 0x5a, (byte) 0x15,
      (byte) 0x20, (byte) 0xed, (byte) 0xde, (byte) 0x32, (byte) 0x76, (byte) 0x0a, (byte) 0xcf,
      (byte) 0xef, (byte) 0xa2, (byte) 0xf4, (byte) 0x2d, (byte) 0x13, (byte) 0xd9, (byte) 0xea,
      (byte) 0x74, (byte) 0x89, (byte) 0xe5, (byte) 0x17, (byte) 0xae, (byte) 0xbf, (byte) 0x1d,
      (byte) 0xbe, (byte) 0x0a, (byte) 0xc4, (byte) 0x4b, (byte) 0xf7, (byte) 0xbb, (byte) 0xc9,
      (byte) 0x33, (byte) 0xd7, (byte) 0x5b, (byte) 0xa3, (byte) 0x45, (byte) 0xf4, (byte) 0xbe,
      (byte) 0x02, (byte) 0xe6, (byte) 0x77, (byte) 0xd7, (byte) 0xfa, (byte) 0xa5, (byte) 0xda,
      (byte) 0x13, (byte) 0x68, (byte) 0x94, (byte) 0x9f, (byte) 0x3e, (byte) 0xff, (byte) 0x15,
      (byte) 0xf4, (byte) 0xd6, (byte) 0xa8, (byte) 0x28, (byte) 0xe1, (byte) 0x3f, (byte) 0x4e,
      (byte) 0xa0, (byte) 0xce, (byte) 0x38, (byte) 0xa5, (byte) 0xb5, (byte) 0x17, (byte) 0x65,
      (byte) 0x14, (byte) 0x06, (byte) 0x6c, (byte) 0xca, (byte) 0xb5, (byte) 0x8f, (byte) 0x70,
      (byte) 0x98, (byte) 0x4d, (byte) 0x2a, (byte) 0xda, (byte) 0xeb, (byte) 0xe9, (byte) 0x07,
      (byte) 0xb8, (byte) 0x09, (byte) 0xe7, (byte) 0x29, (byte) 0x31, (byte) 0x17, (byte) 0xf6,
      (byte) 0x61, (byte) 0x96, (byte) 0xbf, (byte) 0x98, (byte) 0x76, (byte) 0x0d, (byte) 0x93,
      (byte) 0xe1, (byte) 0xf8, (byte) 0xc7, (byte) 0xd1, (byte) 0xc4, (byte) 0xd8, (byte) 0x3a,
      (byte) 0x33, (byte) 0x66, (byte) 0x4e, (byte) 0x84, (byte) 0xbd, (byte) 0x35, (byte) 0x29,
      (byte) 0x51, (byte) 0x32, (byte) 0x34, (byte) 0x02, (byte) 0xcc, (byte) 0x16, (byte) 0xc6,
      (byte) 0xce, (byte) 0xfa, (byte) 0x4f, (byte) 0x11, (byte) 0x9f, (byte) 0x61, (byte) 0x19,
      (byte) 0xf6, (byte) 0xb6, (byte) 0xc1, (byte) 0xa4, (byte) 0xef, (byte) 0x83, (byte) 0x17,
      (byte) 0xf1, (byte) 0x1e, (byte) 0xe6, (byte) 0x08, (byte) 0x76, (byte) 0x7a, (byte) 0xf0,
      (byte) 0xf7, (byte) 0xa2, (byte) 0x9d, (byte) 0xa3, (byte) 0xa5, (byte) 0x69, (byte) 0x02,
      (byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0xee, (byte) 0xb0, (byte) 0x63, (byte) 0x52,
      (byte) 0x47, (byte) 0x7e, (byte) 0x94, (byte) 0x3b, (byte) 0xe5, (byte) 0x0c, (byte) 0x5c,
      (byte) 0x0c, (byte) 0x5f, (byte) 0x9f, (byte) 0xec, (byte) 0xb8, (byte) 0xe6, (byte) 0x81,
      (byte) 0x32, (byte) 0x7b, (byte) 0x2d, (byte) 0xf9, (byte) 0x2c, (byte) 0xa5, (byte) 0x30,
      (byte) 0x86, (byte) 0x2b, (byte) 0xd0, (byte) 0x6f, (byte) 0x64, (byte) 0xfd, (byte) 0xb5,
      (byte) 0xb7, (byte) 0x32, (byte) 0xe4, (byte) 0x02, (byte) 0x2f, (byte) 0x16, (byte) 0x94,
      (byte) 0x95, (byte) 0xae, (byte) 0x7b, (byte) 0x57, (byte) 0xee, (byte) 0x4b, (byte) 0xf0,
      (byte) 0xde, (byte) 0x9d, (byte) 0x54, (byte) 0x29, (byte) 0x99, (byte) 0xcc, (byte) 0xe0,
      (byte) 0xf6, (byte) 0xb5, (byte) 0x17, (byte) 0x03, (byte) 0xfe, (byte) 0xfc, (byte) 0x56,
      (byte) 0x91, (byte) 0x43, (byte) 0x22, (byte) 0xce, (byte) 0x0f, (byte) 0xfa, (byte) 0x08,
      (byte) 0x88, (byte) 0x5e, (byte) 0xb6, (byte) 0x73, (byte) 0xaa, (byte) 0x82, (byte) 0xe7,
      (byte) 0x4c, (byte) 0x2a, (byte) 0xaf, (byte) 0x80, (byte) 0xc6, (byte) 0x83, (byte) 0xab,
      (byte) 0x2a, (byte) 0xdd, (byte) 0xd7, (byte) 0xc1, (byte) 0x15, (byte) 0xdb, (byte) 0x94,
      (byte) 0x98, (byte) 0x0a, (byte) 0x97, (byte) 0x00, (byte) 0x26, (byte) 0x5b, (byte) 0x62,
      (byte) 0x0b, (byte) 0x27, (byte) 0xc3, (byte) 0x64, (byte) 0x38, (byte) 0x98, (byte) 0xd7,
      (byte) 0x26, (byte) 0xcf, (byte) 0x73, (byte) 0x98, (byte) 0xe4, (byte) 0x59, (byte) 0x0a,
      (byte) 0xb1, (byte) 0x06, (byte) 0x1f, (byte) 0x80, (byte) 0x3c, (byte) 0x19, (byte) 0x20,
      (byte) 0x1b, (byte) 0xc3, (byte) 0x47, (byte) 0xaf, (byte) 0x2b, (byte) 0x12, (byte) 0xdf,
      (byte) 0xef, (byte) 0x1d, (byte) 0x4d, (byte) 0xfc, (byte) 0xbd, (byte) 0x02, (byte) 0x81,
      (byte) 0x81, (byte) 0x00, (byte) 0xd3, (byte) 0x74, (byte) 0x85, (byte) 0xf6, (byte) 0xad,
      (byte) 0xdf, (byte) 0x84, (byte) 0xf4, (byte) 0xde, (byte) 0x97, (byte) 0x19, (byte) 0x30,
      (byte) 0xa8, (byte) 0x4a, (byte) 0xf6, (byte) 0x7f, (byte) 0x80, (byte) 0x55, (byte) 0x49,
      (byte) 0xad, (byte) 0x55, (byte) 0x2c, (byte) 0x87, (byte) 0x5f, (byte) 0x29, (byte) 0xda,
      (byte) 0x7a, (byte) 0x81, (byte) 0xd6, (byte) 0xe5, (byte) 0xd8, (byte) 0x8e, (byte) 0x9f,
      (byte) 0xbd, (byte) 0x35, (byte) 0xfe, (byte) 0x82, (byte) 0x0b, (byte) 0x5c, (byte) 0x28,
      (byte) 0x95, (byte) 0x44, (byte) 0xab, (byte) 0x8c, (byte) 0x9e, (byte) 0xa1, (byte) 0xf2,
      (byte) 0x5f, (byte) 0x2a, (byte) 0x6a, (byte) 0x96, (byte) 0x35, (byte) 0xbc, (byte) 0x09,
      (byte) 0x4a, (byte) 0xb1, (byte) 0x19, (byte) 0x2f, (byte) 0xc1, (byte) 0x00, (byte) 0xba,
      (byte) 0x3f, (byte) 0x8b, (byte) 0x9e, (byte) 0x2b, (byte) 0xbd, (byte) 0x0a, (byte) 0x0f,
      (byte) 0x2d, (byte) 0x75, (byte) 0x09, (byte) 0xb6, (byte) 0xea, (byte) 0x98, (byte) 0xb1,
      (byte) 0xff, (byte) 0xd8, (byte) 0x21, (byte) 0x13, (byte) 0x5d, (byte) 0xee, (byte) 0x5b,
      (byte) 0xf2, (byte) 0xad, (byte) 0x46, (byte) 0x81, (byte) 0x9d, (byte) 0x18, (byte) 0x2b,
      (byte) 0x9e, (byte) 0x77, (byte) 0x78, (byte) 0x27, (byte) 0xf5, (byte) 0x3a, (byte) 0x5a,
      (byte) 0xb5, (byte) 0x9b, (byte) 0x02, (byte) 0x66, (byte) 0x1b, (byte) 0xb8, (byte) 0x51,
      (byte) 0x9a, (byte) 0x07, (byte) 0xb7, (byte) 0x3f, (byte) 0x41, (byte) 0x8b, (byte) 0xfe,
      (byte) 0x1e, (byte) 0x85, (byte) 0xc7, (byte) 0xfe, (byte) 0x01, (byte) 0x7a, (byte) 0x7e,
      (byte) 0x2e, (byte) 0xb6, (byte) 0x3b, (byte) 0x64, (byte) 0x6e, (byte) 0xdc, (byte) 0x9d,
      (byte) 0x7a, (byte) 0x48, (byte) 0xd1, (byte) 0x2f, (byte) 0x02, (byte) 0x81, (byte) 0x80,
      (byte) 0x36, (byte) 0x6a, (byte) 0x76, (byte) 0x2a, (byte) 0x42, (byte) 0xec, (byte) 0x63,
      (byte) 0xa5, (byte) 0x08, (byte) 0x01, (byte) 0xfa, (byte) 0x56, (byte) 0x43, (byte) 0xd2,
      (byte) 0xb4, (byte) 0xe8, (byte) 0x2e, (byte) 0x7c, (byte) 0xd3, (byte) 0xe2, (byte) 0x6b,
      (byte) 0x47, (byte) 0xbc, (byte) 0x5a, (byte) 0xe8, (byte) 0xa6, (byte) 0x1e, (byte) 0x05,
      (byte) 0x05, (byte) 0xf0, (byte) 0x53, (byte) 0x3b, (byte) 0x03, (byte) 0x4a, (byte) 0x11,
      (byte) 0xdb, (byte) 0x41, (byte) 0x9a, (byte) 0xf7, (byte) 0x42, (byte) 0xec, (byte) 0xa5,
      (byte) 0x68, (byte) 0x15, (byte) 0x86, (byte) 0xb0, (byte) 0xa2, (byte) 0x3f, (byte) 0xe1,
      (byte) 0xf9, (byte) 0x1d, (byte) 0xfc, (byte) 0x2c, (byte) 0x69, (byte) 0x72, (byte) 0x3d,
      (byte) 0x8e, (byte) 0x06, (byte) 0xaa, (byte) 0xc6, (byte) 0x9d, (byte) 0x95, (byte) 0x5d,
      (byte) 0xb0, (byte) 0xf6, (byte) 0xc9, (byte) 0x7c, (byte) 0xfa, (byte) 0x82, (byte) 0x05,
      (byte) 0x3c, (byte) 0x77, (byte) 0x6a, (byte) 0x22, (byte) 0x8b, (byte) 0x25, (byte) 0xcc,
      (byte) 0x1f, (byte) 0x22, (byte) 0xa2, (byte) 0xcf, (byte) 0xfa, (byte) 0x14, (byte) 0xdb,
      (byte) 0x64, (byte) 0x44, (byte) 0xb4, (byte) 0x6b, (byte) 0xbb, (byte) 0x01, (byte) 0xe7,
      (byte) 0x0c, (byte) 0xfc, (byte) 0xb1, (byte) 0xa6, (byte) 0xb7, (byte) 0x7e, (byte) 0x58,
      (byte) 0x38, (byte) 0x58, (byte) 0x02, (byte) 0xd8, (byte) 0x42, (byte) 0x1b, (byte) 0xd7,
      (byte) 0x71, (byte) 0xca, (byte) 0xd5, (byte) 0x55, (byte) 0xef, (byte) 0xa7, (byte) 0xc2,
      (byte) 0xb4, (byte) 0xbc, (byte) 0x7e, (byte) 0xc9, (byte) 0xe8, (byte) 0x2a, (byte) 0x6c,
      (byte) 0x04, (byte) 0x4e, (byte) 0x60, (byte) 0x9e, (byte) 0x36, (byte) 0xe8, (byte) 0x4a,
      (byte) 0x68, (byte) 0x4d, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x06, (byte) 0x73,
      (byte) 0x24, (byte) 0x6e, (byte) 0xec, (byte) 0xc8, (byte) 0xc7, (byte) 0x96, (byte) 0x6c,
      (byte) 0x7f, (byte) 0xb1, (byte) 0x5e, (byte) 0x01, (byte) 0x94, (byte) 0x1f, (byte) 0xc6,
      (byte) 0xad, (byte) 0xd4, (byte) 0x6c, (byte) 0x25, (byte) 0xe4, (byte) 0x56, (byte) 0x32,
      (byte) 0x5e, (byte) 0xdd, (byte) 0xb8, (byte) 0xf3, (byte) 0x49, (byte) 0xa8, (byte) 0x93,
      (byte) 0x64, (byte) 0x32, (byte) 0x9d, (byte) 0x7e, (byte) 0xb8, (byte) 0xf9, (byte) 0xe5,
      (byte) 0x5f, (byte) 0x91, (byte) 0x55, (byte) 0x0f, (byte) 0x90, (byte) 0x83, (byte) 0xa7,
      (byte) 0x0b, (byte) 0x63, (byte) 0xa7, (byte) 0x2f, (byte) 0xed, (byte) 0xec, (byte) 0x48,
      (byte) 0x5e, (byte) 0xa5, (byte) 0x38, (byte) 0xa7, (byte) 0x55, (byte) 0x95, (byte) 0x8e,
      (byte) 0x16, (byte) 0x55, (byte) 0xfe, (byte) 0x58, (byte) 0x57, (byte) 0xda, (byte) 0xe0,
      (byte) 0x3c, (byte) 0xa8, (byte) 0xe4, (byte) 0xe3, (byte) 0x9f, (byte) 0x11, (byte) 0x47,
      (byte) 0xca, (byte) 0x0a, (byte) 0x14, (byte) 0x4b, (byte) 0xd8, (byte) 0x7c, (byte) 0xd1,
      (byte) 0xc9, (byte) 0x68, (byte) 0xae, (byte) 0xd7, (byte) 0x4d, (byte) 0x1f, (byte) 0xbc,
      (byte) 0x6e, (byte) 0x5d, (byte) 0x41, (byte) 0x5f, (byte) 0x59, (byte) 0x07, (byte) 0x8a,
      (byte) 0x38, (byte) 0x79, (byte) 0xaa, (byte) 0x30, (byte) 0xa5, (byte) 0xe4, (byte) 0xc1,
      (byte) 0xd6, (byte) 0x90, (byte) 0x9d, (byte) 0xb4, (byte) 0x94, (byte) 0x0d, (byte) 0xab,
      (byte) 0xd9, (byte) 0x44, (byte) 0xfa, (byte) 0xe0, (byte) 0x55, (byte) 0x76, (byte) 0x4f,
      (byte) 0x32, (byte) 0x1e, (byte) 0x59, (byte) 0x60, (byte) 0xf5, (byte) 0x60, (byte) 0x04,
      (byte) 0x65, (byte) 0x39, (byte) 0x47, (byte) 0x78, (byte) 0x66, (byte) 0x66, (byte) 0x33,
      (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x37, (byte) 0x90, (byte) 0x1c, (byte) 0x72,
      (byte) 0x46, (byte) 0xc4, (byte) 0xda, (byte) 0x2c, (byte) 0x50, (byte) 0xb8, (byte) 0x4f,
      (byte) 0xdc, (byte) 0x82, (byte) 0x98, (byte) 0xbc, (byte) 0xec, (byte) 0x1d, (byte) 0x84,
      (byte) 0xc1, (byte) 0x33, (byte) 0xb7, (byte) 0x60, (byte) 0x1e, (byte) 0x58, (byte) 0x81,
      (byte) 0x01, (byte) 0x24, (byte) 0x4c, (byte) 0x66, (byte) 0x17, (byte) 0xbc, (byte) 0xc3,
      (byte) 0x83, (byte) 0x0b, (byte) 0x10, (byte) 0x38, (byte) 0x3c, (byte) 0x3c, (byte) 0xb4,
      (byte) 0x36, (byte) 0x0e, (byte) 0x1b, (byte) 0xb5, (byte) 0x93, (byte) 0xd7, (byte) 0x47,
      (byte) 0x14, (byte) 0x48, (byte) 0xf1, (byte) 0xf9, (byte) 0x53, (byte) 0xb5, (byte) 0xe1,
      (byte) 0xe3, (byte) 0x0b, (byte) 0x51, (byte) 0x02, (byte) 0x14, (byte) 0x24, (byte) 0x0c,
      (byte) 0x37, (byte) 0xf5, (byte) 0x78, (byte) 0xac, (byte) 0x00, (byte) 0x9f, (byte) 0xb2,
      (byte) 0xfb, (byte) 0x32, (byte) 0x6c, (byte) 0xef, (byte) 0x2d, (byte) 0xa1, (byte) 0x7c,
      (byte) 0xaf, (byte) 0xbb, (byte) 0x53, (byte) 0x9e, (byte) 0x7a, (byte) 0xc2, (byte) 0x5f,
      (byte) 0x37, (byte) 0x74, (byte) 0xe9, (byte) 0x9b, (byte) 0x2b, (byte) 0xdb, (byte) 0x48,
      (byte) 0xa0, (byte) 0x62, (byte) 0xcb, (byte) 0xee, (byte) 0x80, (byte) 0x07, (byte) 0xdc,
      (byte) 0x0c, (byte) 0xc5, (byte) 0xe6, (byte) 0xc5, (byte) 0xbe, (byte) 0xd8, (byte) 0x82,
      (byte) 0xd1, (byte) 0xd8, (byte) 0xd0, (byte) 0xd5, (byte) 0x8c, (byte) 0x55, (byte) 0xd4,
      (byte) 0xfa, (byte) 0x50, (byte) 0x05, (byte) 0x7a, (byte) 0x02, (byte) 0x6d, (byte) 0xda,
      (byte) 0x56, (byte) 0xec, (byte) 0xca, (byte) 0xf4, (byte) 0x27, (byte) 0xf0, (byte) 0x8f,
      (byte) 0x8f, (byte) 0xc5, (byte) 0x3c, (byte) 0x28, (byte) 0x30
  };

  private static final byte[] ec_key_pkcs8 = {
      (byte) 0x30, (byte) 0x81, (byte) 0x87, (byte) 0x02, (byte) 0x01, (byte) 0x00,
      (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
      (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06,
      (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
      (byte) 0x03, (byte) 0x01, (byte) 0x07, (byte) 0x04, (byte) 0x6d, (byte) 0x30,
      (byte) 0x6b, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x20,
      (byte) 0xfc, (byte) 0x06, (byte) 0xed, (byte) 0x57, (byte) 0xe9, (byte) 0x03,
      (byte) 0xd9, (byte) 0xfe, (byte) 0x3f, (byte) 0x32, (byte) 0x34, (byte) 0x0f,
      (byte) 0xd3, (byte) 0x69, (byte) 0x0a, (byte) 0x4d, (byte) 0xe8, (byte) 0x0b,
      (byte) 0x08, (byte) 0xcd, (byte) 0x17, (byte) 0x1c, (byte) 0x5f, (byte) 0xe5,
      (byte) 0xd3, (byte) 0xaa, (byte) 0x34, (byte) 0xd2, (byte) 0x09, (byte) 0x0b,
      (byte) 0xb2, (byte) 0x1a, (byte) 0xa1, (byte) 0x44, (byte) 0x03, (byte) 0x42,
      (byte) 0x00, (byte) 0x04, (byte) 0xf7, (byte) 0x84, (byte) 0xf4, (byte) 0xae,
      (byte) 0xf2, (byte) 0x80, (byte) 0xca, (byte) 0xe0, (byte) 0xe6, (byte) 0x38,
      (byte) 0x63, (byte) 0x83, (byte) 0x39, (byte) 0x65, (byte) 0xd7, (byte) 0x4c,
      (byte) 0x3d, (byte) 0x75, (byte) 0x13, (byte) 0x7a, (byte) 0x3b, (byte) 0xcd,
      (byte) 0x1a, (byte) 0xca, (byte) 0xa1, (byte) 0x4b, (byte) 0x1d, (byte) 0xa1,
      (byte) 0x6a, (byte) 0xa2, (byte) 0x13, (byte) 0xf5, (byte) 0xf5, (byte) 0xee,
      (byte) 0x90, (byte) 0x92, (byte) 0xeb, (byte) 0x8f, (byte) 0x67, (byte) 0xb1,
      (byte) 0xd0, (byte) 0xa2, (byte) 0x6e, (byte) 0x02, (byte) 0x1a, (byte) 0x83,
      (byte) 0x12, (byte) 0x5b, (byte) 0x68, (byte) 0x8e, (byte) 0x50, (byte) 0x65,
      (byte) 0x35, (byte) 0x66, (byte) 0xa1, (byte) 0xee, (byte) 0x86, (byte) 0x62,
      (byte) 0x22, (byte) 0xe6, (byte) 0x00, (byte) 0x61, (byte) 0x54, (byte) 0x86
  };
  public static byte[] CSR_CHALLENGE = {0x56, 0x78, 0x65, 0x23, (byte) 0xFE, 0x32};

  private CardSimulator simulator;
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMSEProvider cryptoProvider;
  private KMAsn1Parser asn1Parser;

  public KMFunctionalTest() {
    cryptoProvider = new KMJCardSimulator();
    simulator = new CardSimulator();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
  }

  private void init() {
    // Create simulator
    AID appletAID = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID);
    // provision attest key
    KMProvision.provisionCmd(simulator, cryptoProvider, encoder, decoder);
  }

  private void cleanUp() {
    AID appletAID = AIDUtil.create("A000000062");
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID);
  }

  //------------------------------------------------------------------------------------------------
  //  Import key tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testAesImportKeySuccess() {
    init();
    byte[] aesKeySecret = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    short arrPtr = KMArray.instance((short) 5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ECB);
    short blockMode = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PKCS7);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, blockMode);
    KMArray.cast(arrPtr).add((short) 3, paddingMode);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short keyBlob = KMByteBlob.instance(aesKeySecret, (short) 0, (short) 16);
    arrPtr = importKeyNoAttestCmd(keyParams, keyFormatPtr, keyBlob);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_IMPORT_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short byteBlobExp = KMByteBlob.exp();
    short certArrayExp = KMArray.exp(byteBlobExp);
    short ret = KMArray.instance((short) 4);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    KMArray.cast(ret).add((short) 3, certArrayExp);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, sbParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PKCS7));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.ECB));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.AES);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testHmacImportKeySuccess() {
    init();
    byte[] hmacKeySecret = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    short arrPtr = KMArray.instance((short) 5);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short minMacLength = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short) 256));
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, digest);
    KMArray.cast(arrPtr).add((short) 3, minMacLength);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
    short keyBlob = KMByteBlob.instance(hmacKeySecret, (short) 0, (short) 16);
    arrPtr = importKeyNoAttestCmd(keyParams, keyFormatPtr, keyBlob);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_IMPORT_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short byteBlobExp = KMByteBlob.exp();
    short certArrayExp = KMArray.exp(byteBlobExp);
    short ret = KMArray.instance((short) 4);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 2, inst);
    KMArray.cast(ret).add((short) 3, certArrayExp);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, sbParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.HMAC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testRsaImportKeySuccess() {
    init();
    // print(commandAPDU.getBytes());
    ResponseAPDU response = importRsaKey(false);
    short ret = parseImportKeyResponse(response);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    // Self-signed certificate
    short certChain = KMArray.cast(ret).get((short) 3);
    Assert.assertEquals(1, KMArray.cast(certChain).length());
    short byteBlob = KMArray.cast(certChain).get((short) 0);
    Assert.assertTrue("Certificate length should be greater than 0",
        (KMByteBlob.cast(byteBlob).length() > 0));
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, sbParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 2048);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.RSA_PSS));
    tag = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getSignificantShort(),
        0x01);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 0x01);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.RSA);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  @Test
  public void testEcImportKeySuccess() {
    init();
    short arrPtr = KMArray.instance((short) 7);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 256));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, digest);
    KMArray.cast(arrPtr).add((short) 3, ecCurve);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    setDefaultValidity(arrPtr, (short) 5);
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.PKCS8);
    short keyBlob = KMByteBlob.instance(ec_key_pkcs8, (short) 0, (short) ec_key_pkcs8.length);
    arrPtr = importKeyNoAttestCmd(keyParams, keyFormatPtr, keyBlob);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_IMPORT_KEY_CMD, arrPtr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = parseImportKeyResponse(response);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short blobArr = extractKeyBlobArray(KMArray.cast(ret).get((short) 1));
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    // Self-signed certificate
    short certChain = KMArray.cast(ret).get((short) 3);
    Assert.assertEquals(1, KMArray.cast(certChain).length());
    byteBlob = KMArray.cast(certChain).get((short) 0);
    Assert.assertTrue("Certificate length should be greater than 0",
        (KMByteBlob.cast(byteBlob).length() > 0));
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, sbParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ECCURVE, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.P_256);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.EC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.IMPORTED);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  //  Generate key tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testRsaGenerateKeySuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    // Self-signed certificate
    short certChain = KMArray.cast(ret).get((short) 3);
    Assert.assertEquals(1, KMArray.cast(certChain).length());
    short byteBlob = KMArray.cast(certChain).get((short) 0);
    Assert.assertTrue("Certificate length should be greater than 0",
        (KMByteBlob.cast(byteBlob).length() > 0));
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 2048);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.DIGEST_NONE));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.RSA_PKCS1_1_5_ENCRYPT));
    tag = KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getSignificantShort(),
        0x01);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 0x01);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.RSA);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  @Test
  public void testEcGenerateKeySuccess() {
    init();
    short ret = generateEcKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    // Self-signed certificate
    short certChain = KMArray.cast(ret).get((short) 3);
    Assert.assertEquals(1, KMArray.cast(certChain).length());
    short byteBlob = KMArray.cast(certChain).get((short) 0);
    Assert.assertTrue("Certificate length should be greater than 0",
        (KMByteBlob.cast(byteBlob).length() > 0));
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.DIGEST_NONE));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.EC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  @Test
  public void testHmacGenerateKeySuccess() {
    init();
    short ret = generateHmacKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 128);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.SHA2_256));
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 160);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.HMAC);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  @Test
  public void testAesGenerateKeySuccess() {
    init();
    short ret = generateAesDesKey(KMType.AES, (short) 256, null, null, false);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    short keyBlobLength = KMByteBlob.cast(KMArray.cast(ret).get((short) 1)).length();
    short keyCharacteristics = KMArray.cast(ret).get((short) 2);
    short sbParams = KMKeyCharacteristics.cast(keyCharacteristics).getStrongboxEnforced();
    short swParams = KMKeyCharacteristics.cast(keyCharacteristics).getKeystoreEnforced();
    short teeParams = KMKeyCharacteristics.cast(keyCharacteristics).getTeeEnforced();
    Assert.assertEquals(error, KMError.OK);
    short tag = KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, sbParams);
    Assert.assertEquals(KMBoolTag.cast(tag).getVal(), 0x01);
    tag = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, sbParams);
    Assert.assertEquals(KMInteger.cast(KMIntegerTag.cast(tag).getValue()).getShort(), 256);
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.PKCS7));
    tag = KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, sbParams);
    Assert.assertTrue(KMEnumArrayTag.cast(tag).contains(KMType.ECB));
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.AES);
    tag = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ORIGIN, sbParams);
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.GENERATED);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // Helper functions
  //------------------------------------------------------------------------------------------------
  public short generateAesDesKey(byte alg, short keysize, byte[] clientId, byte[] appData,
      boolean unlockReqd) {
    short tagCount = 9;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    if (unlockReqd) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
    short byteBlob = KMByteBlob.instance((short) 3);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ECB);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.CBC);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.CTR);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PKCS7);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, alg));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    tagIndex = setDefaultValidity(arrPtr, tagIndex);
    if (unlockReqd) {
      KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.UNLOCKED_DEVICE_REQUIRED));
    }
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = generateKeyNoAttestCmd(keyParams);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GENERATE_KEY_CMD, arrPtr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    return parseGenerateKeyResponse(response);
  }


  public short parseImportKeyResponse(ResponseAPDU response) {
    return parseGenerateKeyResponse(response);
  }

  public short parseGenerateKeyResponse(ResponseAPDU response) {
    Assert.assertEquals(0x9000, response.getSW());
    short byteBlobExp = KMByteBlob.exp();
    short certArrayExp = KMArray.exp(byteBlobExp);
    short inst = KMKeyCharacteristics.exp();
    short ret = KMArray.instance((short) 4);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    KMArray.cast(ret).add((short) 2, inst);
    KMArray.cast(ret).add((short) 3, certArrayExp);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
    return ret;
  }

  public ResponseAPDU importRsaKey(boolean includeAttestKeyPurpose) {
    byte[] pub = new byte[]{0x00, 0x01, 0x00, 0x01};
    short arrPtr = KMArray.instance((short) 9);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 2048));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    short rsaPubExpTag = KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
        KMInteger.uint_32(pub, (short) 0));
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.RSA_PSS);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    short purposeLength = (short) (includeAttestKeyPurpose ? 2 : 1);
    byteBlob = KMByteBlob.instance((short) purposeLength);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    if (includeAttestKeyPurpose) {
      KMByteBlob.cast(byteBlob).add((short) 1, KMType.ATTEST_KEY);
    }
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    KMArray.cast(arrPtr).add((short) 0, boolTag);
    KMArray.cast(arrPtr).add((short) 1, keySize);
    KMArray.cast(arrPtr).add((short) 2, digest);
    KMArray.cast(arrPtr).add((short) 3, rsaPubExpTag);
    KMArray.cast(arrPtr).add((short) 4, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add((short) 5, padding);
    KMArray.cast(arrPtr).add((short) 6, purpose);
    short nextIndex = setDefaultValidity(arrPtr, (short) 7);
    short keyParams = KMKeyParameters.instance(arrPtr);
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.PKCS8);
    short keyBlob = KMByteBlob.instance(rsa_key_pkcs8, (short) 0, (short) rsa_key_pkcs8.length);
    arrPtr = importKeyNoAttestCmd(keyParams, keyFormatPtr, keyBlob);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_IMPORT_KEY_CMD, arrPtr);
    return simulator.transmitCommand(apdu);
  }


  private short generateRsaKey(byte[] clientId, byte[] appData, short keyUsageLimitPtr) {
    short tagCount = 11;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    if (keyUsageLimitPtr != KMType.INVALID_VALUE) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 2048));
    short byteBlob = KMByteBlob.instance((short) 3);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.SHA2_256);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.SHA1);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 5);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.RSA_PKCS1_1_5_ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.RSA_PKCS1_1_5_SIGN);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.RSA_OAEP);
    KMByteBlob.cast(byteBlob).add((short) 3, KMType.RSA_PSS);
    KMByteBlob.cast(byteBlob).add((short) 4, KMType.PADDING_NONE);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 5);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.VERIFY);
    KMByteBlob.cast(byteBlob).add((short) 2, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 3, KMType.DECRYPT);
    KMByteBlob.cast(byteBlob).add((short) 4, KMType.WRAP_KEY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    byte[] pub = {0, 1, 0, 1};
    short rsaPubExpTag = KMIntegerTag
        .instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, KMInteger.uint_32(pub, (short) 0));
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.INCLUDE_UNIQUE_ID));
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.RESET_SINCE_ID_ROTATION));
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, rsaPubExpTag);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMArray.cast(arrPtr).add(tagIndex++, padding);
    tagIndex = setDefaultValidity(arrPtr, tagIndex);

    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    if (keyUsageLimitPtr != KMType.INVALID_VALUE) {
      KMArray.cast(arrPtr).add(tagIndex++, KMIntegerTag
          .instance(KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT, keyUsageLimitPtr));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = generateKeyNoAttestCmd(keyParams);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    return parseGenerateKeyResponse(response);
  }

  private short generateRsaKey(byte[] clientId, byte[] appData) {
    return generateRsaKey(clientId, appData, KMType.INVALID_VALUE);
  }


  public short generateEcKey(byte[] clientId, byte[] appData) {
    short tagCount = 8;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 256));
    short byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.DIGEST_NONE);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ECCURVE, KMType.P_256));
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
    tagIndex = setDefaultValidity(arrPtr, tagIndex);
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = generateKeyNoAttestCmd(keyParams);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    return parseGenerateKeyResponse(response);
  }


  public short setDefaultValidity(short arrPtr, short index) {
    byte[] undefinedExpirationTime = {0x00, 0x00, (byte) 0xE6, 0x77, (byte) 0xD2, 0x1F, (byte) 0xD8,
        0x18};
    short notBefore = KMInteger.uint_8((byte) 0);
    short notBeforeTag = KMIntegerTag.instance(KMType.DATE_TAG, KMType.CERTIFICATE_NOT_BEFORE,
        notBefore);
    short notAfter = KMInteger.instance(undefinedExpirationTime, (short) 0,
        (short) undefinedExpirationTime.length);
    short notAfterTag = KMIntegerTag.instance(KMType.DATE_TAG, KMType.CERTIFICATE_NOT_AFTER,
        notAfter);
    KMArray.cast(arrPtr).add(index++, notBeforeTag);
    KMArray.cast(arrPtr).add(index++, notAfterTag);
    return index;
  }

  private short extractKeyBlobArray(byte[] buf, short off, short buflen) {
    short byteBlobExp = KMByteBlob.exp();
    short keyChar = KMKeyCharacteristics.exp();
    short keyParam = KMKeyParameters.exp();
    short keyBlob = KMArray.instance(KMKeymasterApplet.ASYM_KEY_BLOB_SIZE_V2);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_VERSION_OFFSET, KMInteger.exp());
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_SECRET, byteBlobExp);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, byteBlobExp);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_NONCE, byteBlobExp);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_PARAMS, keyChar);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_CUSTOM_TAGS, keyParam);
    KMArray.cast(keyBlob).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, byteBlobExp);
    keyBlob = decoder.decodeArray(keyBlob, buf, off, buflen);
    return keyBlob;
  }


  public short generateHmacKey(byte[] clientId, byte[] appData) {
    short tagCount = 8;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.SIGN);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.VERIFY);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short minMacLen = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short)/*256*/160));
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, minMacLen);
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, digest);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.HMAC));
    tagIndex = setDefaultValidity(arrPtr, tagIndex);
    if (clientId != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_ID,
              KMByteBlob.instance(clientId, (short) 0, (short) clientId.length)));
    }
    if (appData != null) {
      KMArray.cast(arrPtr).add(tagIndex++,
          KMByteTag.instance(KMType.APPLICATION_DATA,
              KMByteBlob.instance(appData, (short) 0, (short) appData.length)));
    }
    short keyParams = KMKeyParameters.instance(arrPtr);
    arrPtr = generateKeyNoAttestCmd(keyParams);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GENERATE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    return parseGenerateKeyResponse(response);
  }

  private short extractKeyBlobArray(short keyBlob) {
    return extractKeyBlobArray(KMByteBlob.cast(keyBlob).getBuffer(), KMByteBlob
        .cast(keyBlob).getStartOff(), KMByteBlob.cast(keyBlob).length());
  }

  public short importKeyNoAttestCmd(short keyParams, short keyFormat, short keyBuffer) {
    short emptyBlob = KMByteBlob.instance((short) 0);
    short arrPtr = KMArray.instance((short) 6);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short) 1, keyFormat);
    arg.add((short) 2, keyBuffer);
    arg.add((short) 3, emptyBlob);
    arg.add((short) 4, KMTestUtils.getEmptyKeyParams());
    arg.add((short) 5, emptyBlob);
    return arrPtr;
  }

  public short generateKeyNoAttestCmd(short keyParams) {
    short emptyBlob = KMByteBlob.instance((short) 0);
    short arrPtr = KMArray.instance((short) 4);
    KMArray arg = KMArray.cast(arrPtr);
    arg.add((short) 0, keyParams);
    arg.add((short) 1, emptyBlob);
    arg.add((short) 2, KMTestUtils.getEmptyKeyParams());
    arg.add((short) 3, emptyBlob);
    return arrPtr;
  }
}
