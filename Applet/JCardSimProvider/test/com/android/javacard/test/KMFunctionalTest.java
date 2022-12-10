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
import com.android.javacard.keymaster.KMConfigurations;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMError;
import com.android.javacard.keymaster.KMHardwareAuthToken;
import com.android.javacard.keymaster.KMHmacSharingParameters;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMJCardSimApplet;
import com.android.javacard.keymaster.KMKeyCharacteristics;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMKeymintDataStore;
import com.android.javacard.keymaster.KMOperationState;
import com.android.javacard.keymaster.KMRepository;
import com.android.javacard.keymaster.KMType;
import com.android.javacard.keymaster.KMVerificationToken;
import com.android.javacard.seprovider.KMJCardSimulator;
import com.android.javacard.seprovider.KMSEProvider;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
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

  private void resetAndSelect() {
    simulator.reset();
    AID appletAID = AIDUtil.create("A000000062");
    // Select applet
    simulator.selectApplet(appletAID);
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
  // ImportWrapped Key tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testImportWrappedKeySuccess() {
    init();
    ResponseAPDU response = importWrappedKey();
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
    Assert.assertEquals(KMEnumTag.cast(tag).getValue(), KMType.SECURELY_IMPORTED);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // Device Locked test
  //------------------------------------------------------------------------------------------------
  @Test
  public void testDeviceLocked() {
    init();
    // generate aes key with unlocked_device_required
    short aesKey = generateAesDesKey(KMType.AES, (short) 128, null, null, true);
    short keyBlobPtr = KMArray.cast(aesKey).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    // encrypt something
    short inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    byte[] plainData = "Hello World 123!".getBytes();
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.ENCRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, false, false
    );
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        cipherData, (short) 0, (short) cipherData.length);
    // create verification token
    short verToken = KMVerificationToken.instance();
    KMVerificationToken.cast(verToken).setTimestamp(KMInteger.uint_16((short) 1));
    verToken = signVerificationToken(verToken, KMConfigurations.TEE_MACHINE_TYPE);
    // device locked request
    deviceLock(verToken, KMError.OK);
    inParams = getAesDesParams(KMType.AES, KMType.ECB, KMType.PKCS7, null);
    short beginResp = begin(KMType.ENCRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(inParams), (short) 0, false);
    Assert.assertEquals(KMError.DEVICE_LOCKED,
        KMInteger.cast(KMArray.cast(beginResp).get((short) 0)).getShort());
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // MAX_USES_PER_BOOT use case tests.
  //------------------------------------------------------------------------------------------------
  @Test
  public void testRateLimitExceptsMaxOpsExceeded() {
    init();
    short rsaKeyArr = generateRsaKey(null, null, KMInteger.uint_8((byte) 2));
    Assert.assertEquals(KMInteger.cast(KMArray.cast(rsaKeyArr).get((short) 0)).getShort(),
        KMError.OK);

    // Cache keyblob
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN);
    inParams = KMKeyParameters.instance(inParams);
    // Begin
    begin(KMType.SIGN, keyBlobPtr, inParams, (short) 0, false);

    keyBlobPtr = KMByteBlob.instance((short) keyBlob.length);
    Util.arrayCopyNonAtomic(keyBlob, (short) 0,
        KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        (short) keyBlob.length);
    inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN);
    inParams = KMKeyParameters.instance(inParams);
    begin(KMType.SIGN, keyBlobPtr, inParams, (short) 0, false);

    keyBlobPtr = KMByteBlob.instance((short) keyBlob.length);
    Util.arrayCopyNonAtomic(keyBlob, (short) 0,
        KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        (short) keyBlob.length);
    inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN);
    inParams = KMKeyParameters.instance(inParams);
    short beginResp = begin(KMType.SIGN, keyBlobPtr, inParams, (short) 0, false);
    Assert.assertEquals(KMError.KEY_MAX_OPS_EXCEEDED,
        KMInteger.cast(KMArray.cast(beginResp).get((short) 0)).getShort());
    cleanUp();
  }

  @Test
  public void testRateLimitExceptsTooManyOperations() {
    init();
    byte[] plainData = "Hello World 123!".getBytes();
    for (int i = 0; i <= 8; i++) {
      short rsaKeyArr = generateRsaKey(null, null, KMInteger.uint_8((byte) 1));
      Assert.assertEquals(KMInteger.cast(KMArray.cast(rsaKeyArr).get((short) 0)).getShort(),
          KMError.OK);

      // Cache keyblob
      short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
      short inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN);
      inParams = KMKeyParameters.instance(inParams);
      // Begin
      short beginResp = begin(KMType.SIGN, keyBlobPtr, inParams, (short) 0, false);
      if (i == 8) {
        // Only 8 keys are allowed for MAX_USES_PER_BOOT
        Assert.assertEquals(KMError.TOO_MANY_OPERATIONS,
            KMInteger.cast(KMArray.cast(beginResp).get((short) 0)).getShort());
        return;
      }
      short opHandle = KMArray.cast(beginResp).get((short) 2);
      finish(opHandle,
          KMByteBlob.instance(plainData, (short) 0, (short) plainData.length), null,
          (short) 0, (short) 0, (short) 0, (short) 0, KMError.OK, false);
    }
    cleanUp();
  }

  @Test
  public void testRateLimitClearBufferAfterReboot() {
    init();
    byte[] plainData = "Hello World 123!".getBytes();
    for (int i = 0; i <= 32; i++) {
      if (i % 8 == 0) {
        // Simulate reboot using set boot parameters.
        // Clear the rate limited keys from the flash memory
        KMJCardSimulator.isDeviceRebooted = true;
        KMJCardSimulator.isBootEventSignalSupported = true;
        KMProvision.setAndroidOSSystemProperties(simulator, encoder, decoder,
            (short) KMProvision.OS_VERSION,
            (short) KMProvision.OS_PATCH_LEVEL,
            (short) KMProvision.VENDOR_PATCH_LEVEL);
        KMProvision.computeSharedSecret(simulator, cryptoProvider, encoder, decoder);
        byte[] challenge = KMProvision.getRootOfTrustChallenge(simulator, encoder, decoder);
        KMProvision.sendRootOfTrust(simulator, cryptoProvider, encoder, decoder, challenge);
      }
      short rsaKeyArr = generateRsaKey(null, null, KMInteger.uint_8((byte) 1));
      Assert.assertEquals(KMInteger.cast(KMArray.cast(rsaKeyArr).get((short) 0)).getShort(),
          KMError.OK);

      // Cache keyblob
      short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
      short inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN);
      inParams = KMKeyParameters.instance(inParams);
      // Begin
      short beginResp = begin(KMType.SIGN, keyBlobPtr, inParams, (short) 0, false);
      short opHandle = KMArray.cast(beginResp).get((short) 2);
      // Finish
      finish(opHandle,
          KMByteBlob.instance(plainData, (short) 0, (short) plainData.length), null,
          (short) 0, (short) 0, (short) 0, (short) 0, KMError.OK, false);
    }
    cleanUp();
  }

  @Test
  public void testRateLimitWithHugeCount() {
    init();
    short maxUsesPerBoot = 1000;
    byte[] plainData = "Hello World 123!".getBytes();
    short rsaKeyArr = generateRsaKey(null, null, KMInteger.uint_16(maxUsesPerBoot));
    Assert.assertEquals(KMInteger.cast(KMArray.cast(rsaKeyArr).get((short) 0)).getShort(),
        KMError.OK);

    // Cache keyblob
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);

    for (int i = 0; i <= maxUsesPerBoot; i++) {
      // Cache keyblob
      keyBlobPtr = KMByteBlob.instance((short) keyBlob.length);
      Util.arrayCopyNonAtomic(keyBlob, (short) 0,
          KMByteBlob.cast(keyBlobPtr).getBuffer(),
          KMByteBlob.cast(keyBlobPtr).getStartOff(),
          (short) keyBlob.length);
      short inParams = getRsaParams(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN);
      inParams = KMKeyParameters.instance(inParams);
      // Begin
      short beginResp = begin(KMType.SIGN, keyBlobPtr, inParams, (short) 0, false);
      if (i == maxUsesPerBoot) {
        Assert.assertEquals(KMError.KEY_MAX_OPS_EXCEEDED,
            KMInteger.cast(KMArray.cast(beginResp).get((short) 0)).getShort());
        return;
      }
      short opHandle = KMArray.cast(beginResp).get((short) 2);
      // Finish
      finish(opHandle,
          KMByteBlob.instance(plainData, (short) 0, (short) plainData.length), null,
          (short) 0, (short) 0, (short) 0, (short) 0, KMError.OK, false);
    }
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // GetKeyCharacteristics tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testGetKeyCharacteristicsWithIdDataSuccess() {
    init();
    byte[] clientId = "clientId".getBytes();
    byte[] appData = "appData".getBytes();
    short ret = generateRsaKey(clientId, appData);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    short keyBlob = KMArray.cast(ret).get((short) 1);

    short arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    KMArray.cast(arrPtr)
        .add((short) 1, KMByteBlob.instance(clientId, (short) 0, (short) clientId.length));
    KMArray.cast(arrPtr)
        .add((short) 2, KMByteBlob.instance(appData, (short) 0, (short) appData.length));
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GET_KEY_CHARACTERISTICS_CMD,
        arrPtr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  @Test
  public void testGetKeyCharacteristicsSuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    short keyBlob = KMArray.cast(ret).get((short) 1);

    short arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    KMArray.cast(arrPtr).add((short) 1, KMByteBlob.instance((short) 0));
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.instance((short) 0));
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GET_KEY_CHARACTERISTICS_CMD,
        arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // DeleteKey tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testDeleteKeySuccess() {
    init();
    short ret = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    short len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob, (short) 0);
    ret = getKeyCharacteristics(keyBlobPtr);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
    deleteKey(KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length));
    cleanUp();
  }

  @Test
  public void testDeleteAllKeySuccess() {
    init();
    short ret1 = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(ret1).get((short) 1);
    byte[] keyBlob1 = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    short len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob1, (short) 0);
    short ret2 = generateRsaKey(null, null);
    keyBlobPtr = KMArray.cast(ret2).get((short) 1);
    byte[] keyBlob2 = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    len = KMByteBlob.cast(keyBlobPtr).getValues(keyBlob2, (short) 0);
    CommandAPDU apdu = new CommandAPDU(0x80, INS_DELETE_ALL_KEYS_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder, response));
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // getHmacParams and computeSharedHmac
  //------------------------------------------------------------------------------------------------
  @Test
  public void testComputeHmacParams() {
    init();
    // Get Hmac parameters
    short ret = KMProvision.getHmacSharingParams(simulator, decoder);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
    KMHmacSharingParameters params = KMHmacSharingParameters.cast(KMArray.cast(ret).get((short) 1));
    short seed = params.getSeed();
    short nonce = params.getNonce();

    short params1 = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(params1).setSeed(KMByteBlob.instance((short) 0));
    short num = KMByteBlob.instance((short) 32);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(nonce).getBuffer(),
        KMByteBlob.cast(nonce).getStartOff(),
        KMByteBlob.cast(num).getBuffer(),
        KMByteBlob.cast(num).getStartOff(),
        KMByteBlob.cast(num).length());

    KMHmacSharingParameters.cast(params1).setNonce(num);
    short params2 = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(params2).setSeed(KMByteBlob.instance((short) 0));
    num = KMByteBlob.instance((short) 32);
    cryptoProvider.newRandomNumber(
        KMByteBlob.cast(num).getBuffer(),
        KMByteBlob.cast(num).getStartOff(),
        KMByteBlob.cast(num).length());
    KMHmacSharingParameters.cast(params2).setNonce(num);
    short arr = KMArray.instance((short) 2);
    KMArray.cast(arr).add((short) 0, params1);
    KMArray.cast(arr).add((short) 1, params2);
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, arr);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_COMPUTE_SHARED_HMAC_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    ret = decoder.decode(ret, respBuf, (short) 0, len);
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(0x9000, response.getSW());
    Assert.assertEquals(error, KMError.OK);
    cleanUp();
  }

  @Test
  public void testGetHmacSharingParams() {
    init();
    CommandAPDU commandAPDU = new CommandAPDU(0x80, INS_GET_HMAC_SHARING_PARAM_CMD, KMTestUtils.APDU_P1, KMTestUtils.APDU_P2);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    Assert.assertEquals(0x9000, response.getSW());
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMHmacSharingParameters.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    KMTestUtils.print(respBuf, (short) 0, (short) respBuf.length);
    ret = decoder.decode(ret, respBuf, (short) 0, (short) respBuf.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
    KMHmacSharingParameters params = KMHmacSharingParameters.cast(KMArray.cast(ret).get((short) 1));
    short seed = params.getSeed();
    short nonce = params.getNonce();
    Assert.assertTrue(KMByteBlob.cast(seed).length() == 0);
    Assert.assertTrue(KMByteBlob.cast(nonce).length() == 32);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // AES/DES operations
  //------------------------------------------------------------------------------------------------
  @Test
  public void testWithAesGcmWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.GCM, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesEcbPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithAesCtrNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CTR, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesCtrNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CTR, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithAesEcbNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithDesEcbPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithDesEcbNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesCbcPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithAesCbcNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithDesCbcPkcs7WithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PKCS7, true);
    cleanUp();
  }

  @Test
  public void testWithDesCbcNoPadWithUpdate() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PADDING_NONE, true);
    cleanUp();
  }

  @Test
  public void testWithAesEcbPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithAesCbcPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithAesEcbNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.ECB, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithAesCbcNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.AES, KMType.CBC, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithDesCbcPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testWithDesCbcNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.CBC, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithDesEcbNoPad() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PADDING_NONE, false);
    cleanUp();
  }

  @Test
  public void testWithDesEcbPkcs7() {
    init();
    testEncryptDecryptWithAesDes(KMType.DES, KMType.ECB, KMType.PKCS7, false);
    cleanUp();
  }

  @Test
  public void testUnsupportedBlockMode() {
    init();
    short desKey = generateAesDesKey(KMType.DES, (short) 168, null, null, false);
    short desKeyPtr = KMArray.cast(desKey).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(desKeyPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(desKeyPtr).getBuffer(), KMByteBlob
            .cast(desKeyPtr).getStartOff(), keyBlob, (short) 0,
        (short) keyBlob.length);
    short desPkcs7Params = getAesDesParams(KMType.DES, (byte) KMType.CTR,
        KMType.PKCS7, new byte[12]);
    short ret = begin(KMType.ENCRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(desPkcs7Params), (short) 0, false);
    ret = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(KMError.UNSUPPORTED_BLOCK_MODE, ret);
    cleanUp();
  }

  @Test
  public void testDesEcbPkcs7PaddingCorrupted() {
    init();
    short desKey = generateAesDesKey(KMType.DES, (short) 168, null, null, false);
    short desKeyPtr = KMArray.cast(desKey).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(desKeyPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(desKeyPtr).getBuffer(), KMByteBlob
            .cast(desKeyPtr).getStartOff(), keyBlob, (short) 0,
        (short) keyBlob.length);

    byte[] message = {
        0x61};
    short desPkcs7Params = getAesDesParams(KMType.DES, KMType.ECB,
        KMType.PKCS7, null);
    byte[] cipherText1 = EncryptMessage(message, desPkcs7Params, keyBlob);
    Assert.assertEquals(8, cipherText1.length);
    Assert.assertFalse(Arrays.equals(message, cipherText1));

    // Corrupt the cipher text.
    ++cipherText1[(cipherText1.length / 2)];

    // Decrypt operation
    // Begin
    desPkcs7Params = getAesDesParams(KMType.DES, KMType.ECB, KMType.PKCS7, null);

    short ret = begin(KMType.DECRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(desPkcs7Params), (short) 0, false);
    // Get the operation handle.
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMOperationState.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
        (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

    // Finish
    short dataPtr = KMByteBlob.instance(cipherText1, (short) 0,
        (short) cipherText1.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
    ret = finish(opHandle, dataPtr, null, (short) 0, (short) 0, (short) 0,
        (short) 0, KMError.INVALID_ARGUMENT, false);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // RSA operation tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testWithRsa256Oaep() {
    init();
    testEncryptDecryptWithRsa(KMType.SHA2_256, KMType.RSA_OAEP);
    cleanUp();
  }

  @Test
  public void testWithRsaNonePkcs1() {
    init();
    testEncryptDecryptWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_ENCRYPT);
    cleanUp();
  }

  @Test
  public void testWithRsaNoneNoPad() {
    init();
    testEncryptDecryptWithRsa(KMType.DIGEST_NONE, KMType.PADDING_NONE);
    cleanUp();
  }

  @Test
  public void testSignWithRsaNoneNoPad() {
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.PADDING_NONE, false, false);
    cleanUp();
  }

  @Test
  public void testSignWithRsaNonePkcs1() {
    init();
    testSignVerifyWithRsa(KMType.DIGEST_NONE, KMType.RSA_PKCS1_1_5_SIGN, false, false);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN, false, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithRsaSHA256Pss() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PSS, false, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithRsaSHA256Pkcs1WithUpdate() {
    init();
    testSignVerifyWithRsa(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN, true, true);
    cleanUp();
  }

  @Test
  public void testVtsRsaPkcs1Success() {
    init();
    byte[] message = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
        0x21}; // "Hello World!";
    for (int i = 0; i < 250; i++) {
      short key = generateRsaKey(null, null);
      short rsaKeyPtr = KMArray.cast(key).get((short) 1);
      byte[] keyBlob = new byte[KMByteBlob.cast(rsaKeyPtr).length()];
      Util.arrayCopyNonAtomic(KMByteBlob.cast(rsaKeyPtr).getBuffer(),
          KMByteBlob.cast(rsaKeyPtr).getStartOff(), keyBlob, (short) 0,
          (short) keyBlob.length);
      short pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);

      byte[] cipherText1 = new byte[256];
      short cipherText1Len = rsaEncryptMessage(keyBlob, KMType.RSA_PKCS1_1_5_ENCRYPT,
          KMType.DIGEST_NONE,
          message, (short) 0, (short) message.length,
          cipherText1, (short) 0);
      Assert.assertEquals((2048 / 8), cipherText1Len);

      pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);
      byte[] cipherText2 = new byte[256];
      short cipherText2Len = rsaEncryptMessage(keyBlob, KMType.RSA_PKCS1_1_5_ENCRYPT,
          KMType.DIGEST_NONE,
          message, (short) 0, (short) message.length,
          cipherText2, (short) 0);
      Assert.assertEquals((2048 / 8), cipherText2Len);

      // PKCS1 v1.5 randomizes padding so every result should be different.
      Assert.assertFalse(Arrays.equals(cipherText1, cipherText2));
      //Clean the heap.
      KMRepository.instance().clean();
      pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);
      byte[] plainText = DecryptMessage(cipherText1, pkcs1Params, keyBlob);
      Assert.assertTrue(Arrays.equals(message, plainText));

      // Decrypting corrupted ciphertext should fail.
      short offset_to_corrupt = generateRandom((short) cipherText1.length);

      byte corrupt_byte;
      do {
        corrupt_byte = (byte) generateRandom((short) 256);
      } while (corrupt_byte == cipherText1[offset_to_corrupt]);
      cipherText1[offset_to_corrupt] = corrupt_byte;

      pkcs1Params = getRsaParams(KMType.DIGEST_NONE,
          KMType.RSA_PKCS1_1_5_ENCRYPT);
      // Do Begin operation.
      short ret = begin(KMType.DECRYPT,
          KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
          KMKeyParameters.instance(pkcs1Params), (short) 0, false);

      // Get the operation handle.
      short opHandle = KMArray.cast(ret).get((short) 2);
      byte[] opHandleBuf = new byte[KMOperationState.OPERATION_HANDLE_SIZE];
      KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
          (short) opHandleBuf.length);
      opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

      short dataPtr = KMByteBlob.instance(cipherText1, (short) 0,
          (short) cipherText1.length);
      // Finish should return UNKNOWN_ERROR.
      ret = finish(opHandle, dataPtr, null, (short) 0, (short) 0, (short) 0,
          (short) 0, KMError.UNKNOWN_ERROR, false);
    }
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // HMac operations
  //------------------------------------------------------------------------------------------------
  @Test
  public void testSignVerifyWithHmacSHA256WithUpdate() {
    init();
    testSignVerifyWithHmac(KMType.SHA2_256, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithHmacSHA256() {
    init();
    testSignVerifyWithHmac(KMType.SHA2_256, false);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // ECDSA operation tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testSignVerifyWithEcdsaSHA256WithUpdate() {
    init();
    testSignVerifyWithEcdsa(KMType.SHA2_256, true);
    cleanUp();
  }

  @Test
  public void testSignVerifyWithEcdsaSHA256() {
    init();
    testSignVerifyWithEcdsa(KMType.SHA2_256, false);
    cleanUp();
  }

  //------------------------------------------------------------------------------------------------
  // Provision tests
  //------------------------------------------------------------------------------------------------
  @Test
  public void testVerifyOemLockWithOutSeLockFailure() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionUdsCertChain(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionAttestIds(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionOEMRootPublicKey(simulator, encoder, decoder)));

    ResponseAPDU response = KMProvision.provisionLocked(simulator, encoder, decoder);
    Assert.assertEquals(KMError.UNKNOWN_ERROR, KMTestUtils.decodeError(decoder, response));
    cleanUp();
  }

  @Test
  public void testVerifyOemUnLockAfterOemLockSuccess() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionUdsCertChain(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSeLocked(simulator, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSecureBootMode(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionAttestIds(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionOEMRootPublicKey(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionLocked(simulator, encoder, decoder)));
    // set android system properties
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.setAndroidOSSystemProperties(simulator, encoder, decoder,
            (short) KMProvision.OS_VERSION,
            (short) KMProvision.OS_PATCH_LEVEL,
            (short) KMProvision.VENDOR_PATCH_LEVEL)));
    // negotiate shared secret.
    KMProvision.computeSharedSecret(simulator, cryptoProvider, encoder, decoder);
    byte[] challenge = KMProvision.getRootOfTrustChallenge(simulator, encoder, decoder);
    KMProvision.sendRootOfTrust(simulator, cryptoProvider, encoder, decoder, challenge);
    KMProvision.sendEarlyBootEnded(simulator, decoder);
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionOemUnLock(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionAttestIds(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionLocked(simulator, encoder, decoder)));
    // try generating key
    generateRsaKey(null, null);
    cleanUp();
  }

  @Test
  public void testVerifyOemLockWithOutOemRootKeyFailure() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionUdsCertChain(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSeLocked(simulator, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionAttestIds(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.UNKNOWN_ERROR, KMTestUtils.decodeError(decoder,
        KMProvision.provisionLocked(simulator, encoder, decoder)));
    cleanUp();
  }

  @Test
  public void testVerifySeLockWithOutCertDataSuccess() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSeLocked(simulator, decoder)));
    cleanUp();
  }

  @Test
  public void testVerifyProvisionSeDataAfterSeLockFailure() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionUdsCertChain(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSeLocked(simulator, decoder)));
    Assert.assertEquals(KMError.UNKNOWN_ERROR, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.UNKNOWN_ERROR, KMTestUtils.decodeError(decoder,
        KMProvision.provisionUdsCertChain(simulator, encoder, decoder)));
    cleanUp();
  }

  @Test
  public void testVerifyOemProvisionAfterOemLockFailure() {
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID1);
    // provision attest key
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionDeviceUniqueKeyPair(simulator, cryptoProvider, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionUdsCertChain(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSeLocked(simulator, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSecureBootMode(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionAttestIds(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionOEMRootPublicKey(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder,
        KMProvision.provisionLocked(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.UNKNOWN_ERROR, KMTestUtils.decodeError(decoder,
        KMProvision.provisionSharedSecret(simulator, encoder, decoder)));
    Assert.assertEquals(KMError.UNKNOWN_ERROR, KMTestUtils.decodeError(decoder,
        KMProvision.provisionAttestIds(simulator, encoder, decoder)));
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
    short keyBlob = KMArray.instance(KMKeymasterApplet.ASYM_KEY_BLOB_SIZE_V2_V3);
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


  public short begin(byte keyPurpose, short keyBlob, short keyParmas, short hwToken,
      boolean triggerReset) {
    short arrPtr = KMArray.instance((short) 4);
    KMArray.cast(arrPtr).add((short) 0, KMEnum.instance(KMType.PURPOSE, keyPurpose));
    KMArray.cast(arrPtr).add((short) 1, keyBlob);
    KMArray.cast(arrPtr).add((short) 2, keyParmas);
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    KMArray.cast(arrPtr).add((short) 3, hwToken);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_BEGIN_OPERATION_CMD, arrPtr);
    KMTestUtils.print(apdu.getBytes(), (short) 0, (short) apdu.getBytes().length);
    if (triggerReset) {
      resetAndSelect();
    }
    ResponseAPDU response = simulator.transmitCommand(apdu);
    byte[] respBuf = response.getBytes();
    short arrLen =
        KMTestUtils.readMajorTypeWithPayloadLength(respBuf,
            (short) (KMTestUtils.CBOR_ARRAY_MAJOR_TYPE & 0x00FF));
    short ret;
    if (arrLen == 5) {
      ret = KMArray.instance((short) 5);
      short outParams = KMKeyParameters.exp();
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      KMArray.cast(ret).add((short) 1, outParams);
      KMArray.cast(ret).add((short) 2, KMInteger.exp());// opHandle
      KMArray.cast(ret).add((short) 3, KMInteger.exp());// Buf Mode
      KMArray.cast(ret).add((short) 4, KMInteger.exp());// MacLength

      ret = decoder.decode(ret, respBuf, (short) 0, (short) respBuf.length);
      short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
      Assert.assertEquals(error, KMError.OK);
    } else {
      ret = KMArray.instance((short) 1);
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      ret = decoder.decode(ret, respBuf, (short) 0, (short) respBuf.length);
    }
    return ret;
  }

  public void updateAad(short operationHandle, short data, short hwToken, short verToken) {
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if (verToken == 0) {
      verToken = KMVerificationToken.instance();
    }
    short arrPtr = KMArray.instance((short) 4);
    KMArray.cast(arrPtr).add((short) 0, operationHandle);
    KMArray.cast(arrPtr).add((short) 1, data);
    KMArray.cast(arrPtr).add((short) 2, hwToken);
    KMArray.cast(arrPtr).add((short) 3, verToken);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_UPDATE_AAD_OPERATION_CMD, arrPtr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder, response));
  }

  public short update(short operationHandle, short data, short hwToken,
      short verToken, boolean triggerReset) {
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if (verToken == 0) {
      verToken = KMVerificationToken.instance();
    }
    short arrPtr = KMArray.instance((short) 4);
    KMArray.cast(arrPtr).add((short) 0, operationHandle);
    KMArray.cast(arrPtr).add((short) 1, data);
    KMArray.cast(arrPtr).add((short) 2, hwToken);
    KMArray.cast(arrPtr).add((short) 3, verToken);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_UPDATE_OPERATION_CMD, arrPtr);
    if (triggerReset) {
      resetAndSelect();
    }
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] respBuf = response.getBytes();
    short arrLen = KMTestUtils.readMajorTypeWithPayloadLength(respBuf,
        (short) (KMTestUtils.CBOR_ARRAY_MAJOR_TYPE & 0x00FF));
    short ret;
    if (arrLen == 2) {
      ret = KMArray.instance((short) 2);
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
      ret = decoder.decode(ret, respBuf, (short) 0, (short) respBuf.length);
      Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
    } else {
      ret = KMArray.instance((short) 1);
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      ret = decoder.decode(ret, respBuf, (short) 0, (short) respBuf.length);
    }
    return ret;
  }

  public short finish(short operationHandle, short data, byte[] signature, short inParams,
      short hwToken, short verToken, short confToken, short expectedErr, boolean triggerReset) {
    if (hwToken == 0) {
      hwToken = KMHardwareAuthToken.instance();
    }
    if (verToken == 0) {
      verToken = KMVerificationToken.instance();
    }
    if (confToken == 0) {
      confToken = KMByteBlob.instance((short) 0);
    }
    short signatureTag;
    if (signature == null) {
      signatureTag = KMByteBlob.instance((short) 0);
    } else {
      signatureTag = KMByteBlob.instance(signature, (short) 0, (short) signature.length);
    }
    if (inParams == 0) {
      short arr = KMArray.instance((short) 0);
      inParams = KMKeyParameters.instance(arr);
    }
    short arrPtr = KMArray.instance((short) 6);
    KMArray.cast(arrPtr).add((short) 0, operationHandle);
    KMArray.cast(arrPtr).add((short) 1, data);
    KMArray.cast(arrPtr).add((short) 2, signatureTag);
    KMArray.cast(arrPtr).add((short) 3, hwToken);
    KMArray.cast(arrPtr).add((short) 4, verToken);
    KMArray.cast(arrPtr).add((short) 5, confToken);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_FINISH_OPERATION_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    if (triggerReset) {
      resetAndSelect();
    }
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] respBuf = response.getBytes();
    short arrLen = KMTestUtils.readMajorTypeWithPayloadLength(respBuf,
        (short) (KMTestUtils.CBOR_ARRAY_MAJOR_TYPE & 0x00FF));
    short ret;
    short error;
    if (arrLen == 2) {
      ret = KMArray.instance((short) 2);
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
      KMArray.cast(ret).add((short) 1, KMByteBlob.exp());
    } else {
      ret = KMArray.instance((short) 1);
      KMArray.cast(ret).add((short) 0, KMInteger.exp());
    }
    ret = decoder.decode(ret, respBuf, (short) 0, (short) respBuf.length);
    error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, expectedErr);
    return ret;
  }

  public short processMessage(
      byte[] data,
      short keyBlob,
      byte keyPurpose,
      short inParams,
      short hwToken,
      byte[] signature,
      boolean updateFlag,
      boolean aesGcmFlag) {
    short beginResp = begin(keyPurpose, keyBlob, inParams, hwToken, false);
    short opHandle = KMArray.cast(beginResp).get((short) 2);
    byte[] opHandleBuf = new byte[KMOperationState.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0, (short) opHandleBuf.length);
    short dataPtr = KMByteBlob.instance(data, (short) 0, (short) data.length);
    short ret = KMType.INVALID_VALUE;
    byte[] outputData = new byte[128];
    short len = 0;
    inParams = 0;
    //Test
    short firstDataLen = 16;
    if (keyPurpose == KMType.DECRYPT) {
      firstDataLen = 32;
    }

    //Test

    if (updateFlag) {
      if (aesGcmFlag) {
        byte[] authData = "AuthData".getBytes();
        short associatedData = KMByteBlob.instance(authData, (short) 0, (short) authData.length);
        updateAad(opHandle, associatedData, (short) 0, (short) 0);
      }
      dataPtr = KMByteBlob.instance(data, (short) 0, (short) /*16*/firstDataLen);
      opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
      ret = update(opHandle, dataPtr, (short) 0, (short) 0, false);
      dataPtr = KMArray.cast(ret).get((short) 1);
      if (KMByteBlob.cast(dataPtr).length() > 0) {
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(dataPtr).getBuffer(),
            KMByteBlob.cast(dataPtr).getStartOff(),
            outputData,
            (short) 0,
            KMByteBlob.cast(dataPtr).length());
        len = KMByteBlob.cast(dataPtr).length();
        dataPtr = KMByteBlob.instance(data, len, (short) (data.length - len));
      } else {
        dataPtr = KMByteBlob
            .instance(data, (short)/*16*/firstDataLen, (short) (data.length - /*16*/firstDataLen));
      }
    }

    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);
    if (keyPurpose == KMType.VERIFY) {
      ret = finish(opHandle, dataPtr, signature, (short) 0, (short) 0, (short) 0, (short) 0,
          KMError.OK,
          false);
    } else {
      ret = finish(opHandle, dataPtr, null, (short) 0, (short) 0, (short) 0, (short) 0, KMError.OK,
          false);
    }
    if (len > 0) {
      dataPtr = KMArray.cast(ret).get((short) 1);
      if (KMByteBlob.cast(dataPtr).length() > 0) {
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(dataPtr).getBuffer(),
            KMByteBlob.cast(dataPtr).getStartOff(),
            outputData,
            len,
            KMByteBlob.cast(dataPtr).length());
        len = (short) (len + KMByteBlob.cast(dataPtr).length());
      }
      KMArray.cast(ret).add((short) 1, KMByteBlob.instance(outputData, (short) 0, len));
    }
    return ret;
  }

  private short getAesDesParams(byte alg, byte blockMode, byte padding, byte[] nonce) {
    short inParams;
    if (blockMode == KMType.GCM) {
      inParams = KMArray.instance((short) 4);
      short byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, blockMode);
      KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, padding);
      KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
      short nonceLen = 12;
      byteBlob = KMByteBlob.instance(nonce, (short) 0, nonceLen);
      KMArray.cast(inParams).add((short) 2, KMByteTag.instance(KMType.NONCE, byteBlob));
      short macLen = KMInteger.uint_16((short) 128);
      macLen = KMIntegerTag.instance(KMType.UINT_TAG, KMType.MAC_LENGTH, macLen);
      KMArray.cast(inParams).add((short) 3, macLen);
    } else if (blockMode == KMType.ECB) {
      inParams = KMArray.instance((short) 2);
      short byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, blockMode);
      KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, padding);
      KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
    } else {
      inParams = KMArray.instance((short) 3);
      short byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, blockMode);
      KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob));
      byteBlob = KMByteBlob.instance((short) 1);
      KMByteBlob.cast(byteBlob).add((short) 0, padding);
      KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
      short nonceLen = 16;
      if (alg == KMType.DES) {
        nonceLen = 8;
      }
      byteBlob = KMByteBlob.instance(nonce, (short) 0, nonceLen);
      KMArray.cast(inParams).add((short) 2, KMByteTag.instance(KMType.NONCE, byteBlob));
    }
    return inParams;
  }

  private void deviceLock(short verToken, short expectedError) {
    short req = KMArray.instance((short) 2);
    KMArray.cast(req).add((short) 0, KMInteger.uint_8((byte) 1));
    KMArray.cast(req).add((short) 1, verToken);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_DEVICE_LOCKED_CMD, req);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] respBuf = response.getBytes();
    Assert.assertEquals(expectedError, KMTestUtils.decodeError(decoder, response));
  }

  private short signVerificationToken(short verToken, byte machineType) {
    byte[] scratchPad = new byte[256];
    byte[] authVerification = {
        0x41, 0x75, 0x74, 0x68, 0x20, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
        0x6F,
        0x6E
    };
    // concatenation length will be 37 + length of verified parameters list - which
    // is typically empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopyNonAtomic(authVerification, (short) 0, scratchPad, (short) 0,
        (short) authVerification.length);
    short len = (short) authVerification.length;
    // concatenate challenge - 8 bytes
    short ptr = KMVerificationToken.cast(verToken).getChallenge();
    KMInteger.cast(ptr)
        .value(scratchPad,
            (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.cast(verToken).getTimestamp();
    KMInteger.cast(ptr)
        .value(scratchPad,
            (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate security level - 4 bytes
    scratchPad[(short) (len + 3)] = 1; // TRUSTED_ENVIRONMENT
    len += KMInteger.UINT_32;
    // hmac the data
    short signLen = cryptoProvider.hmacSign(KMKeymintDataStore.instance().getComputedHmacKey(),
        scratchPad, (short) 0, len, scratchPad, len);
    KMVerificationToken.cast(verToken).setMac(KMByteBlob.instance(scratchPad, len, signLen));
    return verToken;
  }

  private short getRsaParams(byte digest, byte padding) {
    short inParams = KMArray.instance((short) 2);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, digest);
    KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, padding);
    KMArray.cast(inParams).add((short) 1, KMEnumArrayTag.instance(KMType.PADDING, byteBlob));
    return inParams;
  }

  private short getEcParams(byte digest) {
    short inParams = KMArray.instance((short) 1);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, digest);
    KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    return inParams;
  }

  public ResponseAPDU importWrappedKey() {
    byte[] wrappedKey = new byte[16];
    cryptoProvider.newRandomNumber(wrappedKey, (short) 0, (short) 16);
    byte[] encWrappedKey = new byte[16];
    byte[] transportKeyMaterial = new byte[32];
    cryptoProvider.newRandomNumber(transportKeyMaterial, (short) 0, (short) 32);
    byte[] nonce = new byte[12];
    cryptoProvider.newRandomNumber(nonce, (short) 0, (short) 12);
    byte[] authData = "Auth Data".getBytes();
    byte[] authTag = new byte[16];
    cryptoProvider.aesGCMEncrypt(transportKeyMaterial, (short) 0, (short) 32, wrappedKey,
        (short) 0, (short) 16, encWrappedKey, (short) 0,
        nonce, (short) 0, (short) 12, authData, (short) 0, (short) authData.length,
        authTag, (short) 0, (short) 16);
    byte[] maskingKey = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
        0, 1, 0, 1, 0, 1, 0};
    byte[] maskedTransportKey = new byte[32];
    for (int i = 0; i < maskingKey.length; i++) {
      maskedTransportKey[i] = (byte) (transportKeyMaterial[i] ^ maskingKey[i]);
    }
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] wrappingKeyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        wrappingKeyBlob, (short) 0, (short) wrappingKeyBlob.length);

    byte[] output = new byte[256];
    short outlen = rsaOaepEncryptMessage(wrappingKeyBlob, KMType.SHA2_256,
        maskedTransportKey, (short) 0, (short) maskedTransportKey.length,
        output, (short) 0);
    Assert.assertTrue((outlen == 256));
    byte[] encTransportKey = new byte[outlen];
    Util.arrayCopyNonAtomic(output, (short) 0, encTransportKey, (short) 0,
        outlen);
    // Begn Import wrapped key.
    // Unwrapping params should have Digest: SHA256 and padding as RSA_OAEP
    short unwrappingParamsArr = KMArray.instance((short) 2);
    // RSA OAEP Padding
    short paddingBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(paddingBlob).add((short) 0, KMType.RSA_OAEP);
    short padding = KMEnumArrayTag.instance(KMType.PADDING, paddingBlob);
    // SHA256 digest
    short digestBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(digestBlob).add((short) 0, KMType.SHA2_256);
    short digest = KMEnumArrayTag.instance(KMType.DIGEST, digestBlob);
    KMArray.cast(unwrappingParamsArr).add((short) 0, padding);
    KMArray.cast(unwrappingParamsArr).add((short) 1, digest);
    short unwrappingParams = KMKeyParameters.instance(unwrappingParamsArr);
    short arr = KMArray.instance((short) 4);
    KMArray.cast(arr).add((short) 0, KMByteBlob.instance(encTransportKey, (short) 0,
        (short) encTransportKey.length)); // Encrypted Transport Key
    KMArray.cast(arr).add((short) 1, KMByteBlob.instance(wrappingKeyBlob, (short) 0,
        (short) wrappingKeyBlob.length)); // Wrapping Key KeyBlob
    KMArray.cast(arr).add((short) 2, KMByteBlob.instance(maskingKey, (short) 0,
        (short) maskingKey.length)); // Masking Key
    KMArray.cast(arr).add((short) 3, unwrappingParams); // unwrapping params
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_BEGIN_IMPORT_WRAPPED_KEY_CMD,
        arr);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] resBuf = response.getBytes();
    short resArr = KMArray.instance((short) 1);
    KMArray.cast(resArr).add((short) 0, KMInteger.exp());
    arr = decoder.decode(resArr, resBuf, (short) 0, (short) resBuf.length);
    Assert.assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(arr).get((short) 0)).getShort());

    // Finish import wrapped key.
    short tagCount = 7;
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16((short) 128));
    short byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ECB);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.CBC);
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
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
    short keyParams = KMKeyParameters.instance(arrPtr);
    arr = KMArray.instance((short) 8);
    KMArray.cast(arr).add((short) 0, keyParams); // Key Params of wrapped key
    KMArray.cast(arr).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW)); // Key Format
    KMArray.cast(arr).add((short) 2, KMByteBlob.instance(encWrappedKey, (short) 0,
        (short) encWrappedKey.length)); // Wrapped Import Key Blob
    KMArray.cast(arr).add((short) 3,
        KMByteBlob.instance(authTag, (short) 0, (short) authTag.length)); // Auth Tag
    KMArray.cast(arr)
        .add((short) 4, KMByteBlob.instance(nonce, (short) 0, (short) nonce.length)); // IV - Nonce
    KMArray.cast(arr).add((short) 5, KMByteBlob.instance(authData, (short) 0,
        (short) authData.length)); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.cast(arr).add((short) 6, KMInteger.uint_8((byte) 0)); // Password Sid
    KMArray.cast(arr).add((short) 7, KMInteger.uint_8((byte) 0)); // Biometric Sid
    apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_FINISH_IMPORT_WRAPPED_KEY_CMD,
        arr);
    response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    return response;
  }

  public short rsaOaepEncryptMessage(byte[] keyBlob, short digest, byte[] input, short inputOff,
      short inputlen,
      byte[] output, short outputOff) {
    byte[] mod = new byte[256];
    if (0 == KMTestUtils.getPublicKey(decoder, keyBlob, (short) 0, (short) keyBlob.length, mod,
        (short) 0)) {
      return 0;
    }
    byte[] exponent = new byte[]{0x01, 0x00, 0x01};

    // Convert byte arrays into keys
    String modString = KMTestUtils.toHexString(mod);
    String expString = KMTestUtils.toHexString(exponent);
    BigInteger modInt = new BigInteger(modString, 16);
    BigInteger expInt = new BigInteger(expString, 16);
    javax.crypto.Cipher rsaCipher = null;
    try {
      KeyFactory kf = KeyFactory.getInstance("RSA");
      // Create cipher with oaep padding
      OAEPParameterSpec oaepSpec = null;
      if (digest == KMType.SHA2_256) {
        oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
      } else {
        oaepSpec = new OAEPParameterSpec("SHA1", "MGF1",
            MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
      }
      rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding", "SunJCE");

      RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modInt, expInt);
      java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey) kf
          .generatePublic(pubSpec);
      rsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pubKey, oaepSpec);
      byte[] cipherOut = rsaCipher.doFinal(input, inputOff, inputlen);

      if (cipherOut != null) {
        Util.arrayCopyNonAtomic(cipherOut, (short) 0, output, outputOff, (short) cipherOut.length);
      }
      return (short) cipherOut.length;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    }
    return 0;
  }

  public short getKeyCharacteristics(short keyBlob) {
    short arrPtr = KMArray.instance((short) 3);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    KMArray.cast(arrPtr).add((short) 1, KMByteBlob.instance((short) 0));
    KMArray.cast(arrPtr).add((short) 2, KMByteBlob.instance((short) 0));
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, (byte) INS_GET_KEY_CHARACTERISTICS_CMD,
        arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    short ret = KMArray.instance((short) 2);
    KMArray.cast(ret).add((short) 0, KMInteger.exp());
    short inst = KMKeyCharacteristics.exp();
    KMArray.cast(ret).add((short) 1, inst);
    byte[] respBuf = response.getBytes();
    short len = (short) respBuf.length;
    if (len > 5) {
      ret = decoder.decode(ret, respBuf, (short) 0, len);
    } else {
      ret = KMByteBlob.instance(respBuf, (short) 0, len);
    }
    return ret;
  }

  private void deleteKey(short keyBlob) {
    short arrPtr = KMArray.instance((short) 1);
    KMArray.cast(arrPtr).add((short) 0, keyBlob);
    CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_DELETE_KEY_CMD, arrPtr);
    // print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(KMError.OK, KMTestUtils.decodeError(decoder, response));
  }

  public void testEncryptDecryptWithAesDes(byte alg, byte blockMode, byte padding, boolean update) {
    short aesDesKeyArr;
    boolean aesGcmFlag = false;
    if (alg == KMType.AES) {
      if (blockMode == KMType.GCM) {
        aesDesKeyArr = generateAesGcmKey((short) 128, null, null);
        aesGcmFlag = true;
      } else {
        aesDesKeyArr = generateAesDesKey(alg, (short) 128, null, null, false);
      }
    } else {
      aesDesKeyArr = generateAesDesKey(alg, (short) 168, null, null, false);
    }
    short keyBlobPtr = KMArray.cast(aesDesKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    byte[] nonce = new byte[16];
    cryptoProvider.newRandomNumber(nonce, (short) 0, (short) 16);
    short inParams = getAesDesParams(alg, blockMode, padding, nonce);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Encrypt
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.ENCRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, aesGcmFlag
    );
    inParams = getAesDesParams(alg, blockMode, padding, nonce);
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    //print(keyBlobPtr);
    byte[] cipherData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        cipherData, (short) 0, (short) cipherData.length);
    ret = processMessage(cipherData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.DECRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, aesGcmFlag
    );
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    //print(plainData,(short)0,(short)plainData.length);
    //print(keyBlobPtr);
    short equal = Util.arrayCompare(plainData, (short) 0, KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(), (short) plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testEncryptDecryptWithRsa(byte digest, byte padding) {
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    byte[] plainData = "Hello World 123!".getBytes();
    byte[] cipherData = new byte[256];
    short cipherDataLen = 0;
    //Encrypt
    if (padding == KMType.RSA_OAEP) {
      cipherDataLen = rsaOaepEncryptMessage(keyBlob, digest, plainData,
          (short) 0, (short) plainData.length, cipherData, (short) 0);
    } else {
      cipherDataLen = rsaEncryptMessage(keyBlob, padding, digest, plainData,
          (short) 0, (short) plainData.length, cipherData, (short) 0);
    }
    Assert.assertTrue((cipherDataLen == 256));
    short inParams = getRsaParams(digest, padding);
    short ret = processMessage(cipherData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.DECRYPT,
        KMKeyParameters.instance(inParams),
        (short) 0, null, false, false
    );
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    short len = KMByteBlob.cast(keyBlobPtr).length();
    short start = KMByteBlob.cast(keyBlobPtr).getStartOff();
    short equal = Util.arrayCompare(plainData, (short) 0, KMByteBlob.cast(keyBlobPtr).getBuffer(),
        (short) (start + len - plainData.length), (short) plainData.length);
    Assert.assertTrue(equal == 0);
  }

  public void testSignVerifyWithRsa(byte digest, byte padding, boolean update, boolean verifyFlag) {
    short rsaKeyArr = generateRsaKey(null, null);
    short keyBlobPtr = KMArray.cast(rsaKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getRsaParams(digest, padding);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Sign
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.SIGN,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, false
    );
    inParams = getRsaParams(digest, padding);
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        signatureData, (short) 0, (short) signatureData.length);
    if (verifyFlag == false) {
      Assert.assertEquals(signatureData.length, 256);
      return;
    }
    boolean verify = rsaVerifyMessage(plainData, (short) 0, (short) plainData.length,
        signatureData, (short) 0, (short) signatureData.length,
        digest, padding, keyBlob);
    Assert.assertTrue(verify);
  }

  public void testSignVerifyWithEcdsa(byte digest, boolean update) {
    short ecKeyArr = generateEcKey(null, null);
    short keyBlobPtr = KMArray.cast(ecKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getEcParams(digest);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Sign
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.SIGN,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, false
    );
    inParams = getEcParams(digest);
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        signatureData, (short) 0, (short) signatureData.length);
    boolean verify = false;
    if (digest == KMType.DIGEST_NONE) {
      verify = ecNoDigestVerifyMessage(plainData, (short) 0, (short) plainData.length,
          signatureData, (short) 0, (short) signatureData.length,
          keyBlob);
    } else {
      verify = ecVerifyMessage(plainData, (short) 0, (short) plainData.length,
          signatureData, (short) 0, (short) signatureData.length,
          keyBlob);
    }
    Assert.assertTrue(verify);
  }

  public void testSignVerifyWithHmac(byte digest, boolean update) {
    short hmacKeyArr = generateHmacKey(null, null);
    short keyBlobPtr = KMArray.cast(hmacKeyArr).get((short) 1);
    byte[] keyBlob = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        keyBlob, (short) 0, (short) keyBlob.length);
    short inParams = getHmacParams(digest, true);
    byte[] plainData = "Hello World 123!".getBytes();
    if (update) {
      plainData = "Hello World 123! Hip Hip Hoorah!".getBytes();
    }
    //Sign
    short ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.SIGN,
        KMKeyParameters.instance(inParams),
        (short) 0, null, update, false
    );
    inParams = getHmacParams(digest, false);
    keyBlobPtr = KMArray.cast(ret).get((short) 1);
    byte[] signatureData = new byte[KMByteBlob.cast(keyBlobPtr).length()];
    Util.arrayCopyNonAtomic(KMByteBlob.cast(keyBlobPtr).getBuffer(),
        KMByteBlob.cast(keyBlobPtr).getStartOff(),
        signatureData, (short) 0, (short) signatureData.length);
    ret = processMessage(plainData,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMType.VERIFY,
        KMKeyParameters.instance(inParams),
        (short) 0, signatureData, update, false
    );
    short error = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
    Assert.assertEquals(error, KMError.OK);
  }

  private short getHmacParams(byte digest, boolean sign) {
    short paramsize = (short) (sign ? 2 : 1);
    short inParams = KMArray.instance((short) paramsize);
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, digest);
    KMArray.cast(inParams).add((short) 0, KMEnumArrayTag.instance(KMType.DIGEST, byteBlob));
    short macLength = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MAC_LENGTH, KMInteger.uint_16((short)/*256*/160));
    if (sign) {
      KMArray.cast(inParams).add((short) 1, macLength);
    }
    return inParams;
  }

  public boolean ecNoDigestVerifyMessage(byte[] input, short inputOff,
      short inputlen, byte[] sign, short signOff, short signLen,
      byte[] keyBlob) {
    KeyFactory kf;
    byte[] pubKey = new byte[128];
    short keyStart = 0;
    short keyLength = KMTestUtils.getPublicKey(decoder, keyBlob, (short) 0, (short) keyBlob.length,
        pubKey, (short) 0);
    if (keyLength == 0) {
      return false;
    }
    try {
      java.security.Signature sunSigner = java.security.Signature.getInstance(
          "NONEwithECDSA", "SunEC");
      kf = KeyFactory.getInstance("EC");
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC",
          "SunEC");
      // Supported curve secp256r1
      parameters.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecParameters = parameters
          .getParameterSpec(ECParameterSpec.class);

      // Check if the first byte is 04 and remove it.
      if (pubKey[keyStart] == 0x04) {
        // uncompressed format.
        keyStart++;
        keyLength--;
      }
      short i = 0;
      byte[] pubx = new byte[keyLength / 2];
      for (; i < keyLength / 2; i++) {
        pubx[i] = pubKey[keyStart + i];
      }
      byte[] puby = new byte[keyLength / 2];
      for (i = 0; i < keyLength / 2; i++) {
        puby[i] = pubKey[keyStart + keyLength / 2 + i];
      }
      BigInteger bIX = new BigInteger(pubx);
      BigInteger bIY = new BigInteger(puby);
      ECPoint point = new ECPoint(bIX, bIY);
      ECPublicKeySpec pubkeyspec = new ECPublicKeySpec(point, ecParameters);
      java.security.interfaces.ECPublicKey ecPubkey = (java.security.interfaces.ECPublicKey) kf
          .generatePublic(pubkeyspec);
      sunSigner.initVerify(ecPubkey);
      sunSigner.update(input, inputOff, inputlen);
      return sunSigner.verify(sign, signOff, signLen);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    } catch (InvalidParameterSpecException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (SignatureException e) {
      e.printStackTrace();
    }
    return false;
  }

  public boolean ecVerifyMessage(byte[] input, short inputOff, short inputlen,
      byte[] sign, short signOff, short signLen, byte[] keyBlob) {
    Signature ecVerifier;
    byte[] pubKey = new byte[128];
    short len = KMTestUtils.getPublicKey(decoder, keyBlob, (short) 0, (short) keyBlob.length,
        pubKey, (short) 0);
    if (len == 0) {
      return false;
    }
    ECPublicKey key = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setW(pubKey, (short) 0, len);
    ecVerifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    ecVerifier.init(key, Signature.MODE_VERIFY);
    return ecVerifier.verify(input, inputOff, inputlen, sign, signOff, signLen);
  }

  public boolean rsaVerifyMessage(byte[] input, short inputOff, short inputlen, byte[] sign,
      short signOff, short signLen,
      short digest, short padding, byte[] keyBlob) {
    if (digest == KMType.DIGEST_NONE || padding == KMType.PADDING_NONE) {
      return false;
    }
    byte[] pubKey = new byte[256];
    if (0 == KMTestUtils.getPublicKey(decoder, keyBlob, (short) 0, (short) keyBlob.length, pubKey,
        (short) 0)) {
      return false;
    }
    short alg = Signature.ALG_RSA_SHA_256_PKCS1_PSS;

    if (padding == KMType.RSA_PKCS1_1_5_SIGN) {
      alg = Signature.ALG_RSA_SHA_256_PKCS1;
    }

    Signature rsaVerifier = Signature.getInstance((byte) alg, false);
    RSAPublicKey key = (RSAPublicKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
    byte[] exponent = new byte[]{0x01, 0x00, 0x01};
    key.setExponent(exponent, (short) 0, (short) exponent.length);
    key.setModulus(pubKey, (short) 0, (short) pubKey.length);
    rsaVerifier.init(key, Signature.MODE_VERIFY);
    return rsaVerifier.verify(input, inputOff, inputlen, sign, signOff, signLen);
  }

  public byte[] EncryptMessage(byte[] input, short params, byte[] keyBlob) {
    short ret = begin(KMType.ENCRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(params), (short) 0, false);
    // Get the operation handle.
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMOperationState.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
        (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

    ret = finish(opHandle,
        KMByteBlob.instance(input, (short) 0, (short) input.length), null,
        (short) 0, (short) 0, (short) 0, (short) 0, KMError.OK, false);
    short dataPtr = KMArray.cast(ret).get((short) 1);
    byte[] output = new byte[KMByteBlob.cast(dataPtr).length()];
    if (KMByteBlob.cast(dataPtr).length() > 0) {
      Util.arrayCopyNonAtomic(KMByteBlob.cast(dataPtr).getBuffer(), KMByteBlob
              .cast(dataPtr).getStartOff(), output, (short) 0,
          KMByteBlob.cast(dataPtr).length());
    }
    return output;
  }

  public byte[] DecryptMessage(byte[] input, short params, byte[] keyBlob) {
    short ret = begin(KMType.DECRYPT,
        KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length),
        KMKeyParameters.instance(params), (short) 0, false);
    // Get the operation handle.
    short opHandle = KMArray.cast(ret).get((short) 2);
    byte[] opHandleBuf = new byte[KMOperationState.OPERATION_HANDLE_SIZE];
    KMInteger.cast(opHandle).getValue(opHandleBuf, (short) 0,
        (short) opHandleBuf.length);
    opHandle = KMInteger.uint_64(opHandleBuf, (short) 0);

    ret = finish(opHandle,
        KMByteBlob.instance(input, (short) 0, (short) input.length), null,
        (short) 0, (short) 0, (short) 0, (short) 0, KMError.OK, false);
    short dataPtr = KMArray.cast(ret).get((short) 1);
    byte[] output = new byte[KMByteBlob.cast(dataPtr).length()];
    if (KMByteBlob.cast(dataPtr).length() > 0) {
      Util.arrayCopyNonAtomic(KMByteBlob.cast(dataPtr).getBuffer(), KMByteBlob
              .cast(dataPtr).getStartOff(), output, (short) 0,
          KMByteBlob.cast(dataPtr).length());
    }
    return output;
  }

  public short generateRandom(short upperBound) {
    Random rand = new Random();
    short int_random = (short) rand.nextInt(upperBound);
    return int_random;
  }

  public short generateAesGcmKey(short keysize, byte[] clientId, byte[] appData) {
    short tagCount = 10;
    if (clientId != null) {
      tagCount++;
    }
    if (appData != null) {
      tagCount++;
    }
    short arrPtr = KMArray.instance(tagCount);
    short boolTag = KMBoolTag.instance(KMType.NO_AUTH_REQUIRED);
    short keySize = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.KEYSIZE, KMInteger.uint_16(keysize));
    short macLength = KMIntegerTag
        .instance(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, KMInteger.uint_16((short) 96));
    short byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.GCM);
    short blockModeTag = KMEnumArrayTag.instance(KMType.BLOCK_MODE, byteBlob);
    byteBlob = KMByteBlob.instance((short) 1);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.PADDING_NONE);
    short paddingMode = KMEnumArrayTag.instance(KMType.PADDING, byteBlob);
    byteBlob = KMByteBlob.instance((short) 2);
    KMByteBlob.cast(byteBlob).add((short) 0, KMType.ENCRYPT);
    KMByteBlob.cast(byteBlob).add((short) 1, KMType.DECRYPT);
    short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob);
    short tagIndex = 0;
    KMArray.cast(arrPtr).add(tagIndex++, boolTag);
    KMArray.cast(arrPtr).add(tagIndex++, macLength);
    KMArray.cast(arrPtr).add(tagIndex++, keySize);
    KMArray.cast(arrPtr).add(tagIndex++, blockModeTag);
    KMArray.cast(arrPtr).add(tagIndex++, paddingMode);
    KMArray.cast(arrPtr).add(tagIndex++, KMEnumTag.instance(KMType.ALGORITHM, KMType.AES));
    KMArray.cast(arrPtr).add(tagIndex++, purpose);
    KMArray.cast(arrPtr).add(tagIndex++, KMBoolTag.instance(KMType.CALLER_NONCE));
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

  public short rsaEncryptMessage(byte[] keyBlob, short padding, short digest, byte[] input,
      short inputOff, short inputlen,
      byte[] output, short outputOff) {
    byte alg = Cipher.ALG_RSA_PKCS1;
    byte[] tmp = null;
    short inLen = inputlen;
    if (padding == KMType.PADDING_NONE) {
      alg = Cipher.ALG_RSA_NOPAD;
      // Length cannot be greater then key size according to JcardSim
      if (inLen >= 256) {
        return 0;
      }
      // make input equal to 255 bytes
      tmp = new byte[255];
      Util.arrayFillNonAtomic(tmp, (short) 0, (short) 255, (byte) 0);
      Util.arrayCopyNonAtomic(
          input,
          inputOff,
          tmp, (short) (255 - inLen), inLen);
      inLen = 255;
      inputOff = 0;
    } else if (padding == KMType.RSA_PKCS1_1_5_ENCRYPT) {
      tmp = input;
    } else {
      /*Fail */
      Assert.assertTrue(false);
    }
    byte[] pubKey = new byte[256];
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    RSAPublicKey rsaPubKey = (RSAPublicKey) rsaKeyPair.getPublic();
    if (0 == KMTestUtils.getPublicKey(decoder, keyBlob, (short) 0, (short) keyBlob.length, pubKey,
        (short) 0)) {
      return 0;
    }

    byte[] exponent = new byte[]{0x01, 0x00, 0x01};
    rsaPubKey.setModulus(pubKey, (short) 0, (short) pubKey.length);
    rsaPubKey.setExponent(exponent, (short) 0, (short) exponent.length);

    Cipher rsaCipher = Cipher.getInstance(alg, false);
    rsaCipher.init(rsaPubKey, Cipher.MODE_ENCRYPT);
    return rsaCipher.doFinal(tmp, inputOff, inLen, output, outputOff);
  }
}
