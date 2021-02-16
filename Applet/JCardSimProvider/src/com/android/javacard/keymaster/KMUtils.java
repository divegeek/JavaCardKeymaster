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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import javacard.framework.Util;

public class KMUtils {

  // 64 bit unsigned calculations for time
  public static final byte[] oneSecMsec = {
      0, 0, 0, 0, 0, 0, 0x03, (byte) 0xE8}; // 1000 msec
  public static final byte[] oneMinMsec = {
      0, 0, 0, 0, 0, 0, (byte) 0xEA, 0x60}; // 60000 msec
  public static final byte[] oneHourMsec = {
      0, 0, 0, 0, 0, 0x36, (byte) 0xEE, (byte) 0x80}; // 3600000 msec
  public static final byte[] oneDayMsec = {
      0, 0, 0, 0, 0x05, 0x26, 0x5C, 0x00}; // 86400000 msec
  public static final byte[] oneMonthMsec = {
      0, 0, 0, 0, (byte) 0x9C, (byte) 0xBE, (byte) 0xBD, 0x50}; // 2629746000 msec
  public static final byte[] leapYearMsec = {
      0, 0, 0, 0x07, (byte) 0x5C, (byte) 0xD7, (byte) 0x88, 0x00}; //31622400000;
  public static final byte[] yearMsec = {
      0, 0, 0, 0x07, 0x57, (byte) 0xB1, 0x2C, 0x00}; //31536000000
  //Leap year(366) + 3 * 365
  public static final byte[] fourYrsMsec = {
      0, 0, 0, 0x1D, 0x63, (byte) 0xEB, 0x0C, 0x00};//126230400000
  public static final byte[] firstJan2020 = {
      0, 0, 0x01, 0x6F, 0x5E, 0x66, (byte) 0xE8, 0x00}; // 1577836800000 msec
  public static final byte[] firstJan2051 = {
      0, 0, 0x02, 0x53, 0x26, (byte) 0x0E, (byte) 0x1C, 0x00}; // 2556144000000
  // msec
  public static final byte[] febMonthLeapMSec = {
      0, 0, 0, 0, (byte) 0x95, 0x58, 0x6C, 0x00}; //2505600000
  public static final byte[] febMonthMsec = {
      0, 0, 0, 0, (byte) 0x90, 0x32, 0x10, 0x00}; //2419200000
  public static final byte[] ThirtyOneDaysMonthMsec = {
      0, 0, 0, 0, (byte) 0x9F, (byte) 0xA5, 0x24, 0x00};//2678400000
  public static final byte[] ThirtDaysMonthMsec = {
      0, 0, 0, 0, (byte) 0x9A, 0x7E, (byte) 0xC8, 0x00};//2592000000
  public static final short year2051 = 2051;
  public static final short year2020 = 2020;

  // --------------------------------------
  public static short convertToDate(short time, byte[] scratchPad,
      boolean utcFlag) {

    short yrsCount = 0;
    short monthCount = 1;
    short dayCount = 1;
    short hhCount = 0;
    short mmCount = 0;
    short ssCount = 0;
    byte Z = 0x5A;
    boolean from2020 = true;
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    Util.arrayCopyNonAtomic(KMInteger.cast(time).getBuffer(),
        KMInteger.cast(time).getStartOff(), scratchPad,
        (short) (8 - KMInteger.cast(time).length()), KMInteger.cast(time)
            .length());
    // If the time is less then 1 Jan 2020 then it is an error
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, firstJan2020, (short) 0,
        (short) 8) < 0) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (utcFlag
        && KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, firstJan2051,
        (short) 0, (short) 8) >= 0) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, firstJan2051, (short) 0,
        (short) 8) < 0) {
      Util.arrayCopyNonAtomic(firstJan2020, (short) 0, scratchPad, (short) 8,
          (short) 8);
      subtract(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    } else {
      from2020 = false;
      Util.arrayCopyNonAtomic(firstJan2051, (short) 0, scratchPad, (short) 8,
          (short) 8);
      subtract(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    }
    // divide the given time with four yrs msec count
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, fourYrsMsec, (short) 0,
        (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(fourYrsMsec, (short) 0, scratchPad, (short) 8,
          (short) 8);
      yrsCount = divide(scratchPad, (short) 0, (short) 8, (short) 16); // quotient
      // is
      // multiple
      // of 4
      yrsCount = (short) (yrsCount * 4); // number of yrs.
      // copy reminder as new dividend
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    }

    //Get the leap year index starting from the (base Year + yrsCount) Year.
    short leapYrIdx = getLeapYrIndex(from2020, yrsCount);

    // if leap year index is 0, then the number of days for the 1st year will be 366 days.
    // if leap year index is not 0, then the number of days for the 1st year will be 365 days.
    if (((leapYrIdx == 0) &&
        (KMInteger
            .unsignedByteArrayCompare(scratchPad, (short) 0, leapYearMsec, (short) 0, (short) 8)
            >= 0)) ||
        ((leapYrIdx != 0) &&
            (KMInteger
                .unsignedByteArrayCompare(scratchPad, (short) 0, yearMsec, (short) 0, (short) 8)
                >= 0))) {
      for (short i = 0; i < 4; i++) {
        yrsCount++;
        if (i == leapYrIdx) {
          Util.arrayCopyNonAtomic(leapYearMsec, (short) 0, scratchPad,
              (short) 8, (short) 8);
        } else {
          Util.arrayCopyNonAtomic(yearMsec, (short) 0, scratchPad, (short) 8,
              (short) 8);
        }
        subtract(scratchPad, (short) 0, (short) 8, (short) 16);
        Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
            (short) 8);
        if (((short) (i + 1) == leapYrIdx)) {
          if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, leapYearMsec,
              (short) 0, (short) 8) < 0) {
            break;
          }
        } else {
          if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, yearMsec,
              (short) 0, (short) 8) < 0) {
            break;
          }
        }
      }
    }

    // total yrs from 1970
    if (from2020) {
      yrsCount = (short) (year2020 + yrsCount);
    } else {
      yrsCount = (short) (year2051 + yrsCount);
    }

    // divide the given time with one month msec count
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, oneMonthMsec, (short) 0,
        (short) 8) >= 0) {
      for (short i = 0; i < 12; i++) {
        if (i == 1) {
          // Feb month
          if (isLeapYear(yrsCount)) {
            // Leap year 29 days
            Util.arrayCopyNonAtomic(febMonthLeapMSec, (short) 0, scratchPad,
                (short) 8, (short) 8);
          } else {
            // 28 days
            Util.arrayCopyNonAtomic(febMonthMsec, (short) 0, scratchPad,
                (short) 8, (short) 8);
          }
        } else if (((i <= 6) && ((i % 2 == 0))) || ((i > 6) && ((i % 2 == 1)))) {
          Util.arrayCopyNonAtomic(ThirtyOneDaysMonthMsec, (short) 0,
              scratchPad, (short) 8, (short) 8);
        } else {
          // 30 Days
          Util.arrayCopyNonAtomic(ThirtDaysMonthMsec, (short) 0, scratchPad,
              (short) 8, (short) 8);
        }

        if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, scratchPad, (short) 8,
            (short) 8) >= 0) {
          subtract(scratchPad, (short) 0, (short) 8, (short) 16);
          Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
              (short) 8);
        } else {
          break;
        }
        monthCount++;
      }
    }

    // divide the given time with one day msec count
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, oneDayMsec, (short) 0,
        (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneDayMsec, (short) 0, scratchPad, (short) 8,
          (short) 8);
      dayCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      dayCount++;
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    }

    // divide the given time with one hour msec count
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, oneHourMsec, (short) 0,
        (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneHourMsec, (short) 0, scratchPad, (short) 8,
          (short) 8);
      hhCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    }

    // divide the given time with one minute msec count
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, oneMinMsec, (short) 0,
        (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneMinMsec, (short) 0, scratchPad, (short) 8,
          (short) 8);
      mmCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    }

    // divide the given time with one second msec count
    if (KMInteger.unsignedByteArrayCompare(scratchPad, (short) 0, oneSecMsec, (short) 0,
        (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneSecMsec, (short) 0, scratchPad, (short) 8,
          (short) 8);
      ssCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
          (short) 8);
    }

    // Now convert to ascii string YYMMDDhhmmssZ or YYYYMMDDhhmmssZ
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    short len = numberToString(yrsCount, scratchPad, (short) 0); // returns YYYY
    len += numberToString(monthCount, scratchPad, len);
    len += numberToString(dayCount, scratchPad, len);
    len += numberToString(hhCount, scratchPad, len);
    len += numberToString(mmCount, scratchPad, len);
    len += numberToString(ssCount, scratchPad, len);
    scratchPad[len] = Z;
    len++;
    if (utcFlag) {
      return KMByteBlob.instance(scratchPad, (short) 2, (short) (len - 2)); // YY
    } else {
      return KMByteBlob.instance(scratchPad, (short) 0, len); // YYYY
    }
  }

  public static short numberToString(short number, byte[] scratchPad,
      short offset) {
    byte zero = 0x30;
    byte len = 2;
    byte digit;
    if (number > 999) {
      len = 4;
    }
    byte index = len;
    while (index > 0) {
      digit = (byte) (number % 10);
      number = (short) (number / 10);
      scratchPad[(short) (offset + index - 1)] = (byte) (digit + zero);
      index--;
    }
    return len;
  }

  // Use Euclid's formula: dividend = quotient*divisor + remainder
  // i.e. dividend - quotient*divisor = remainder where remainder < divisor.
  // so this is division by subtraction until remainder remains.
  public static short divide(byte[] buf, short dividend, short divisor,
      short remainder) {
    short expCnt = 1;
    short q = 0;
    // first increase divisor so that it becomes greater then dividend.
    while (compare(buf, divisor, dividend) < 0) {
      shiftLeft(buf, divisor);
      expCnt = (short) (expCnt << 1);
    }
    // Now subtract divisor from dividend if dividend is greater then divisor.
    // Copy remainder in the dividend and repeat.
    while (expCnt != 0) {
      if (compare(buf, dividend, divisor) >= 0) {
        subtract(buf, dividend, divisor, remainder);
        copy(buf, remainder, dividend);
        q = (short) (q + expCnt);
      }
      expCnt = (short) (expCnt >> 1);
      shiftRight(buf, divisor);
    }
    return q;
  }

  public static void copy(byte[] buf, short from, short to) {
    Util.arrayCopyNonAtomic(buf, from, buf, to, (short) 8);
  }

  public static byte compare(byte[] buf, short lhs, short rhs) {
    return KMInteger.unsignedByteArrayCompare(buf, lhs, buf, rhs, (short) 8);
  }

  public static void shiftLeft(byte[] buf, short start) {
    byte index = 7;
    byte carry = 0;
    byte tmp;
    while (index >= 0) {
      tmp = buf[(short) (start + index)];
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] << 1);
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] + carry);
      if (tmp < 0) {
        carry = 1;
      } else {
        carry = 0;
      }
      index--;
    }
  }

  public static void shiftRight(byte[] buf, short start) {
    byte index = 0;
    byte carry = 0;
    byte tmp;
    while (index < 8) {
      tmp = (byte) (buf[(short) (start + index)] & 0x01);
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] >> 1);
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] & 0x7F);
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] | carry);
      if (tmp == 1) {
        carry = (byte) 0x80;
      } else {
        carry = 0;
      }
      index++;
    }
  }

  public static void add(byte[] buf, short op1, short op2, short result) {
    byte index = 7;
    byte carry = 0;
    short tmp;
    while (index >= 0) {
      tmp = (short) (buf[(short) (op1 + index)] + buf[(short) (op2 + index)] + carry);
      carry = 0;
      if (tmp > 255) {
        carry = 1; // max unsigned byte value is 255
      }
      buf[(short) (result + index)] = (byte) (tmp & (byte) 0xFF);
      index--;
    }
  }

  // subtraction by borrowing.
  public static void subtract(byte[] buf, short op1, short op2, short result) {
    byte borrow = 0;
    byte index = 7;
    short r;
    short x;
    short y;
    while (index >= 0) {
      x = (short) (buf[(short) (op1 + index)] & 0xFF);
      y = (short) (buf[(short) (op2 + index)] & 0xFF);
      r = (short) (x - y - borrow);
      borrow = 0;
      if (r < 0) {
        borrow = 1;
        r = (short) (r + 256); // max unsigned byte value is 255
      }
      buf[(short) (result + index)] = (byte) (r & 0xFF);
      index--;
    }
  }

  public static short countTemporalCount(byte[] bufTime, short timeOff,
      short timeLen, byte[] scratchPad, short offset) {
    Util.arrayFillNonAtomic(scratchPad, (short) offset, (short) 24, (byte) 0);
    Util.arrayCopyNonAtomic(
        bufTime,
        timeOff,
        scratchPad,
        (short) (offset + 8 - timeLen),
        timeLen);
    Util.arrayCopyNonAtomic(oneMonthMsec, (short) 0, scratchPad, (short) (offset + 8),
        (short) 8);
    return divide(scratchPad, (short) 0, (short) 8, (short) 16);
  }

  public static boolean isLeapYear(short year) {
    if ((short) (year % 4) == (short) 0) {
      if (((short) (year % 100) == (short) 0) &&
          ((short) (year % 400)) != (short) 0) {
        return false;
      }
      return true;
    }
    return false;
  }

  public static short getLeapYrIndex(boolean from2020, short yrsCount) {
    short newBaseYr = (short) (from2020 ? (year2020 + yrsCount) : (year2051 + yrsCount));
    for (short i = 0; i < 4; i++) {
      if (isLeapYear((short) (newBaseYr + i))) {
        return i;
      }
    }
    return -1;
  }

}