package com.android.javacard.keymaster;

import javacard.framework.Util;

public class KMUtils {
  // 64 bit unsigned calculations for time
  public static final byte[] oneSecMsec = {
          0, 0, 0, 0, 0, 0, 0x03, (byte) 0xE8 }; // 1000 msec
  public static final byte[] oneMinMsec = {
          0, 0, 0, 0, 0, 0, (byte) 0xEA, 0x60 }; // 60000 msec
  public static final byte[] oneHourMsec = {
          0, 0, 0, 0, 0, 0x36, (byte) 0xEE, (byte) 0x80 }; // 3600000 msec
  public static final byte[] oneDayMsec = {
          0, 0, 0, 0, 0x05, 0x26, 0x5C, 0x00 }; // 86400000 msec
  public static final byte[] oneMonthMsec = {
          0, 0, 0, 0, (byte) 0x9A, 0x7E, (byte) 0xC8, 0x00 }; // 2592000000 msec
  public static final byte[] oneYearMsec = {
          0, 0, 0, 0x07, 0x57, (byte) 0xB1, 0x2C, 0x00 }; // 31536000000 msec
  // Leap year + 3 yrs
  public static final byte[] fourYrsMsec = {
          0, 0, 0, 0x1D, 0x63, (byte) 0xEB, 0x0C, 0x00 }; // 126230400000 msec
  public static final byte[] firstJan2020 = {
          0, 0, 0x01, 0x6F, 0x60, 0x1E, 0x5C, 0x00 }; // 1577865600000 msec
  public static final byte[] firstJan2051 = {
          0, 0, 0x02, 0x53, 0x27, (byte) 0xC5, (byte) 0x90, 0x00 }; // 2556172800000
                                                                    // msec

  // --------------------------------------
  public static short convertToDate(short time, byte[] scratchPad,
          boolean utcFlag) {
    short yrsCount = 0;
    short monthCount = 0;
    short dayCount = 0;
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
    if (Util.arrayCompare(scratchPad, (short) 0, firstJan2020, (short) 0,
            (short) 8) < 0) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (utcFlag
            && Util.arrayCompare(scratchPad, (short) 0, firstJan2051,
                    (short) 0, (short) 8) >= 0) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    if (Util.arrayCompare(scratchPad, (short) 0, firstJan2051, (short) 0,
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
    if (Util.arrayCompare(scratchPad, (short) 0, fourYrsMsec, (short) 0,
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
    // divide the given time with one yr msec count
    if (Util.arrayCompare(scratchPad, (short) 0, oneYearMsec, (short) 0,
            (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneYearMsec, (short) 0, scratchPad, (short) 8,
              (short) 8);
      yrsCount += divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
              (short) 8);
    }
    // total yrs from 1970
    if (from2020)
      yrsCount = (short) (2020 + yrsCount);
    else
      yrsCount = (short) (2051 + yrsCount);

    // divide the given time with one month msec count
    if (Util.arrayCompare(scratchPad, (short) 0, oneMonthMsec, (short) 0,
            (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneMonthMsec, (short) 0, scratchPad, (short) 8,
              (short) 8);
      monthCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
              (short) 8);
    }

    // divide the given time with one day msec count
    if (Util.arrayCompare(scratchPad, (short) 0, oneDayMsec, (short) 0,
            (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneDayMsec, (short) 0, scratchPad, (short) 8,
              (short) 8);
      dayCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
              (short) 8);
    }

    // divide the given time with one hour msec count
    if (Util.arrayCompare(scratchPad, (short) 0, oneHourMsec, (short) 0,
            (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneHourMsec, (short) 0, scratchPad, (short) 8,
              (short) 8);
      hhCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
              (short) 8);
    }

    // divide the given time with one minute msec count
    if (Util.arrayCompare(scratchPad, (short) 0, oneMinMsec, (short) 0,
            (short) 8) >= 0) {
      Util.arrayCopyNonAtomic(oneMinMsec, (short) 0, scratchPad, (short) 8,
              (short) 8);
      mmCount = divide(scratchPad, (short) 0, (short) 8, (short) 16);
      Util.arrayCopyNonAtomic(scratchPad, (short) 16, scratchPad, (short) 0,
              (short) 8);
    }

    // divide the given time with one second msec count
    if (Util.arrayCompare(scratchPad, (short) 0, oneSecMsec, (short) 0,
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
    if (utcFlag)
      return KMByteBlob.instance(scratchPad, (short) 2, (short) (len - 2)); // YY
    else
      return KMByteBlob.instance(scratchPad, (short) 0, len); // YYYY
  }

  public static short numberToString(short number, byte[] scratchPad,
          short offset) {
    byte zero = 0x30;
    byte len = 2;
    byte digit;
    if (number > 999)
      len = 4;
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
    return Util.arrayCompare(buf, lhs, buf, rhs, (short) 8);
  }

  public static void shiftLeft(byte[] buf, short start) {
    byte index = 7;
    byte carry = 0;
    byte tmp;
    while (index >= 0) {
      tmp = buf[(short) (start + index)];
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] << 1);
      buf[(short) (start + index)] = (byte) (buf[(short) (start + index)] + carry);
      if (tmp < 0)
        carry = 1;
      else
        carry = 0;
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
      if (tmp == 1)
        carry = (byte) 0x80;
      else
        carry = 0;
      index++;
    }
  }

  
  // num1 must be greater then or equal to num2 and both must be positive
  /*private short subtractIntegers(short num1, short num2) {
    short buf =
    repository.alloc((short)24); byte[] scratchPad = repository.getHeap();
    Util.arrayFillNonAtomic(scratchPad, buf, (short) 24, (byte) 0);
    Util.arrayCopyNonAtomic(KMInteger.cast(num1).getBuffer(),
            KMInteger.cast(num1).getStartOff(), scratchPad,
            (short) (buf + 8 - KMInteger.cast(num1).length()),
            KMInteger.cast(num1).length());
    Util.arrayCopyNonAtomic(KMInteger.cast(num2).getBuffer(),
            KMInteger.cast(num2).getStartOff(), scratchPad,
            (short) (buf + 16 - KMInteger.cast(num2).length()),
            KMInteger.cast(num2).length());
    if (scratchPad[buf] < 0 || scratchPad[(short) (buf + 8)] < 0)
      return KMType.INVALID_VALUE;
    if (Util.arrayCompare(scratchPad, buf, scratchPad, (short) (buf + 8),
            (short) 8) < 1)
      return KMType.INVALID_VALUE;
    subtract(scratchPad, buf, (short) (buf + 8), (short) (buf + 16));
    return KMInteger.uint_64(scratchPad, (short) (buf + 16));
  }*/

  public static void add(byte[] buf, short op1, short op2, short result) {
    byte index = 7;
    byte carry = 0;
    short tmp;
    while (index >= 0) {
      tmp = (short) (buf[(short) (op1 + index)] + buf[(short) (op2 + index)] + carry);
      carry = 0;
      if (tmp > 255)
        carry = 1; // max unsigned byte value is 255
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

}
