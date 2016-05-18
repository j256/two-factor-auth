package com.j256.totp;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Two factor Java implementation for the Time-based One-Time Password (TOTP) algorithm.
 * 
 * See: https://github.com/j256/java-two-factor-auth
 * 
 * Copyright 2015, Gray Watson
 * 
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby
 * granted provided that the above copyright notice and this permission notice appear in all copies. THE SOFTWARE IS
 * PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
 * OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 * @author graywatson
 */
public class TwoFactorAuthUtil {

	/** default time-step which is part of the spec, 30 seconds is default */
	public static final int TIME_STEP_SECONDS = 30;
	/** set to the number of digits to control 0 prefix, set to 0 for no prefix */
	private static int NUM_DIGITS_OUTPUT = 6;

	private final String blockOfZeros;

	{
		StringBuilder sb = new StringBuilder(NUM_DIGITS_OUTPUT);
		for (int i = 0; i < NUM_DIGITS_OUTPUT; i++) {
			sb.append('0');
		}
		blockOfZeros = sb.toString();
	}

	/**
	 * Generate a secret key in base32 format (A-Z2-7)
	 */
	public String generateBase32Secret() {
		StringBuilder sb = new StringBuilder();
		Random random = new SecureRandom();
		for (int i = 0; i < 16; i++) {
			int val = random.nextInt(32);
			if (val < 26) {
				sb.append((char) ('A' + val));
			} else {
				sb.append((char) ('2' + (val - 26)));
			}
		}
		return sb.toString();
	}

	/**
	 * Return the current number to be checked. This can be compared against user input.
	 * 
	 * WARNING: This requires a system clock that is in sync with the world.
	 * 
	 * For more details of this magic algorithm, see:
	 * http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
	 */
	public String generateCurrentNumber(String secret) throws GeneralSecurityException {
		return generateCurrentNumber(secret, System.currentTimeMillis());
	}

	/**
	 * Same as {@link #generateCurrentNumber(String)} except at a particular time in millis. Mostly for testing
	 * purposes.
	 */
	public String generateCurrentNumber(String secret, long currentTimeMillis) throws GeneralSecurityException {

		byte[] key = decodeBase32(secret);

		byte[] data = new byte[8];
		long value = currentTimeMillis / 1000 / TIME_STEP_SECONDS;
		for (int i = 7; value > 0; i--) {
			data[i] = (byte) (value & 0xFF);
			value >>= 8;
		}

		// encrypt the data with the key and return the SHA1 of it in hex
		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
		// if this is expensive, could put in a thread-local
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		// take the 4 least significant bits from the encrypted string as an offset
		int offset = hash[hash.length - 1] & 0xF;

		// We're using a long because Java hasn't got unsigned int.
		long truncatedHash = 0;
		for (int i = offset; i < offset + 4; ++i) {
			truncatedHash <<= 8;
			// get the 4 bytes at the offset
			truncatedHash |= (hash[i] & 0xFF);
		}
		// cut off the top bit
		truncatedHash &= 0x7FFFFFFF;

		// the token is then the last 6 digits in the number
		truncatedHash %= 1000000;

		return zeroPrepend(truncatedHash, NUM_DIGITS_OUTPUT);
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program
	 * as an easy way to enter the secret.
	 * 
	 * NOTE: this must be URL escaped if it is to be put into a href on a web-page.
	 */
	public String qrImageUrl(String keyId, String secret) {
		StringBuilder sb = new StringBuilder(128);
		sb.append("https://chart.googleapis.com/chart");
		sb.append("?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=");
		sb.append("otpauth://totp/").append(keyId).append("%3Fsecret%3D").append(secret);
		return sb.toString();
	}

	/**
	 * Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
	 */
	String zeroPrepend(long num, int digits) {
		String hashStr = Long.toString(num);
		if (hashStr.length() >= digits) {
			return hashStr;
		} else {
			StringBuilder sb = new StringBuilder(digits);
			int zeroCount = digits - hashStr.length();
			sb.append(blockOfZeros, 0, zeroCount);
			sb.append(hashStr);
			return sb.toString();
		}
	}

	/**
	 * Little decode base-32 method. We could use Apache Codec but I didn't want to have the dependency just for this
	 * decode method. Exposed for testing.
	 */
	byte[] decodeBase32(String str) {
		// each base-32 character encodes 5 bits
		int numBytes = ((str.length() * 5) + 4) / 8;
		byte[] result = new byte[numBytes];
		int resultIndex = 0;
		int which = 0;
		int working = 0;
		for (int i = 0; i < str.length(); i++) {
			char ch = str.charAt(i);
			int val;
			if (ch >= 'a' && ch <= 'z') {
				val = ch - 'a';
			} else if (ch >= 'A' && ch <= 'Z') {
				val = ch - 'A';
			} else if (ch >= '2' && ch <= '7') {
				val = 26 + (ch - '2');
			} else if (ch == '=') {
				// special case
				which = 0;
				break;
			} else {
				throw new IllegalArgumentException("Invalid base-32 character: " + ch);
			}
			/*
			 * There are probably better ways to do this but this seemed the most straightforward.
			 */
			switch (which) {
				case 0 :
					// all 5 bits is top 5 bits
					working = (val & 0x1F) << 3;
					which = 1;
					break;
				case 1 :
					// top 3 bits is lower 3 bits
					working |= (val & 0x1C) >> 2;
					result[resultIndex++] = (byte) working;
					// lower 2 bits is upper 2 bits
					working = (val & 0x03) << 6;
					which = 2;
					break;
				case 2 :
					// all 5 bits is mid 5 bits
					working |= (val & 0x1F) << 1;
					which = 3;
					break;
				case 3 :
					// top 1 bit is lowest 1 bit
					working |= (val & 0x10) >> 4;
					result[resultIndex++] = (byte) working;
					// lower 4 bits is top 4 bits
					working = (val & 0x0F) << 4;
					which = 4;
					break;
				case 4 :
					// top 4 bits is lowest 4 bits
					working |= (val & 0x1E) >> 1;
					result[resultIndex++] = (byte) working;
					// lower 1 bit is top 1 bit
					working = (val & 0x01) << 7;
					which = 5;
					break;
				case 5 :
					// all 5 bits is mid 5 bits
					working |= (val & 0x1F) << 2;
					which = 6;
					break;
				case 6 :
					// top 2 bits is lowest 2 bits
					working |= (val & 0x18) >> 3;
					result[resultIndex++] = (byte) working;
					// lower 3 bits of byte 6 is top 3 bits
					working = (val & 0x07) << 5;
					which = 7;
					break;
				case 7 :
					// all 5 bits is lower 5 bits
					working |= (val & 0x1F);
					result[resultIndex++] = (byte) working;
					which = 0;
					break;
			}
		}
		if (which != 0) {
			result[resultIndex++] = (byte) working;
		}
		if (resultIndex != result.length) {
			result = Arrays.copyOf(result, resultIndex);
		}
		return result;
	}
}
