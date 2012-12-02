package it.j4ops.util;


/*
 * Created on 24-giu-2005
 *
 * This class represents a TLV (Tag Length Value) structure. There are methods
 * for creating trees consisting of TLV objects from ASN.1 BER encoded byte
 * sequences and for creating byte sequences from TLV object trees. All
 * manipulations are done on the tree structure.
 */
/**
 * @author fzanutto
 *
 * TODO To change the template for this generated type comment go to Window - Preferences - Java - Code Style - Code Templates
 */
public class HexString
{
  /** Auxillary string array. */
  protected final static String[] hexChars = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" };

  /**
   * Hex-dump a byte array (offset and printable ASCII included)
   * <p>
   *
   * @param data
   *          Byte array to convert to HexString
   *
   * @return HexString
   */
  public static String dump(byte[] data) {
    return dump(data, 0, data.length);
  }

  /**
   * Hex-dump a byte array (offset and printable ASCII included)
   * <p>
   *
   * @param data
   *          Byte array to convert to HexString
   * @param offset
   *          Start dump here
   * @param len
   *          Number of bytes to be dumped.
   * @return HexString
   */
  public static String dump(byte[] data, int offset, int len) {
    if (data == null)
      return "null";
    char[] ascii = new char[16];
    StringBuilder out = new StringBuilder(256);
    for (int i = offset; i < offset + len;) {
      // offset
      out.append(hexify((i >>> 8) & 0xff));
      out.append(hexify(i & 0xff));
      out.append(":  ");
      // hexbytes
      for (int j = 0; j < 16; j++, i++) {
        if (i < data.length) {
          int b = data[i] & 0xff;
          out.append(hexify(b)).append(' ');
          ascii[j] = (b >= 32 && b < 127) ? (char) b : '.';
        }
        else {
          out.append("   ");
          ascii[j] = ' ';
        }
      }
      // ASCII
      out.append(' ').append(ascii).append("\n");
    }
    return out.toString();
  }

  /**
   * Hexify a byte array.
   * <p>
   *
   * @param data
   *          Byte array to convert to HexString
   *
   * @return HexString
   */
  public static String hexify(byte[] data, boolean space) {
    if (data == null) {
      return "null";
    }

    StringBuilder out = new StringBuilder((data.length * 2) + 10);
    int n = 0;
    for (byte aData : data) {
      if (space) {
          if (n > 0)
              out.append(' ');
      }
      out.append(hexChars[(aData >> 4) & 0x0f]);
      out.append(hexChars[aData & 0x0f]);
      if (++n == 16) {
          if (space) {
              out.append('\n');
          }
          n = 0;
      }
    }
    return out.toString();
  }

  /**
   * Hexify a byte array.
   * <p>
   *
   * @param data
   *          Byte array to convert to HexString
   *
   * @return HexString
   */
  public static String hexify(byte[] data, int offset, int len) {
    if (data == null)
      return "null";
    StringBuilder out = new StringBuilder(256);
    for (int i = offset; i < len - offset; i++) {
      out.append(hexChars[(data[i] >> 4) & 0x0f]);
      out.append(hexChars[data[i] & 0x0f]);
    }
    return out.toString();
  }


  /**
   * Hexify a byte array.
   * <p>
   *
   * @param data
   *          Byte array to convert to HexString
   *
   * @return HexString
   */
  public static String hexify(byte[] data) {
    if (data == null)
      return "null";
    StringBuilder out = new StringBuilder(256);
    for (int i = 0; i < data.length; i++) {
      out.append(hexChars[(data[i] >> 4) & 0x0f]);
      out.append(hexChars[data[i] & 0x0f]);
    }
    return out.toString();
  }

  public static String binify(byte[] data, boolean space) {
    if (data == null)
      return "null";
    StringBuilder out = new StringBuilder((data.length * 8) + 10);
    int n = 0;
    for (int i = 0; i < data.length; i++)
    {
      if (space)
      {
        if (n > 0)
          out.append(' ');
      }

      for (int bit = 7; bit >= 0; bit --)
      {
    	if (((data[i] >>> bit) & 0x01) == 0x01)
    	{
    		out.append('1');
    	}
    	else
    	{
    		out.append('0');
    	}
      }


      if (++n == 16)
      {
        if (space)
        {
          out.append('\n');
        }
        n = 0;
      }

    }
    return out.toString();
  }


  /**
   * Hexify a byte value.
   * <p>
   *
   * @param val
   *          Byte value to be displayed as a HexString.
   *
   * @return HexString
   */
  public static String hexify(int val)
  {
    return hexChars[((val & 0xff) & 0xf0) >>> 4] + hexChars[val & 0x0f];
  }

  /**
   * Hexify short value encoded in two bytes.
   * <p>
   *
   * @param a
   *          High byte of short value to be hexified
   * @param b
   *          Low byte of short value to be hexified
   *
   * @return HexString
   */
  public static String hexifyShort(byte a, byte b)
  {
    return hexifyShort(a & 0xff, b & 0xff);
  }

  /**
   * Hexify a short value.
   * <p>
   *
   * @param val
   *          Short value to be displayed as a HexString.
   *
   * @return HexString
   */
  public static String hexifyShort(int val)
  {
    return hexChars[((val & 0xffff) & 0xf000) >>> 12] + hexChars[((val & 0xfff) & 0xf00) >>> 8] + hexChars[((val & 0xff) & 0xf0) >>> 4] + hexChars[val & 0x0f];
  }

  /**
   * Hexify short value encoded in two (int-encoded)bytes.
   * <p>
   *
   * @param a
   *          High byte of short value to be hexified
   * @param b
   *          Low byte of short value to be hexified
   *
   * @return HexString
   */
  public static String hexifyShort(int a, int b)
  {
    return hexifyShort(((a & 0xff) << 8) + (b & 0xff));
  }

  /**
   * Parse bytes encoded as Hexadecimals into a byte array.
   * <p>
   *
   * @param byteString
   *          String containing HexBytes.
   *
   * @return byte array containing the parsed values of the given string.
   */
  public static byte[] parseHexString(String byteString)
  {
    byte[] result = new byte[byteString.length() / 2];
    for (int i = 0; i < byteString.length(); i += 2)
    {
      String toParse = byteString.substring(i, i + 2);
      result[i / 2] = (byte) Integer.parseInt(toParse, 16);
    }
    return result;
  }

  /**
   * Parse string of Hexadecimals into a byte array suitable for unsigned BigInteger computations. Reverse the order of the parsed data on the fly (input data little endian).
   * <p>
   *
   * @param byteString
   *          String containing HexBytes.
   *
   * @return byte array containing the parsed values of the given string.
   */
  public static byte[] parseLittleEndianHexString(String byteString)
  {
    byte[] result = new byte[byteString.length() / 2 + 1];
    for (int i = 0; i < byteString.length(); i += 2)
    {
      String toParse = byteString.substring(i, i + 2);
      result[(byteString.length() - i) / 2] = (byte) Integer.parseInt(toParse, 16);
    }
    result[0] = (byte) 0; // just to make it a positive value
    return result;
  }

    public static byte[] intToByteArray(int value) {
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        return b;
    }

    public static byte [] BinToHex (String bin)
    {
        byte []arr = new byte [bin.length ()/8];
        int pos = 0;
        int test = 0;
        for (int index = 0; index < bin.length (); index ++)
        {
            int val = 0;
            if (bin.charAt (index) == '1')
            {
                val = 1;
            }
            arr[test] = (byte)((arr[test] << 1) | val);

            if (pos == 7)
            {
                pos = 0;
                test ++;
            }
            else
            {
                pos ++;
            }
        }
        return arr;
    }
}
