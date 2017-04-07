package com.j256.twofactorauth;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java implementation for the Time-based One-Time Password (TOTP) two factor authentication algorithm. To get this to
 * work you:
 * 
 * <ol>
 * <li>Use generateBase32Secret() to generate a secret key for a user.</li>
 * <li>Store the secret key in the database associated with the user account.</li>
 * <li>Display the QR image URL returned by qrImageUrl(...) to the user.</li>
 * <li>User uses the image to load the secret key into his authenticator application.</li>
 * </ol>
 * 
 * <p>
 * Whenever the user logs in:
 * </p>
 * 
 * <ol>
 * <li>The user enters the number from the authenticator application into the login form.</li>
 * <li>Read the secret associated with the user account from the database.</li>
 * <li>The server compares the user input with the output from generateCurrentNumber(...).</li>
 * <li>If they are equal then the user is allowed to log in.</li>
 * </ol>
 * 
 * <p>
 * See: https://github.com/j256/two-factor-auth
 * </p>
 * 
 * <p>
 * For more details of this magic algorithm, see: http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
 * </p>
 * 
 * @author graywatson
 */
public class TimeBasedOneTimePasswordUtil {

	/** default time-step which is part of the spec, 30 seconds is default */
	public static final int DEFAULT_TIME_STEP_SECONDS = 30;
	/** set to the number of digits to control 0 prefix, set to 0 for no prefix */
	private static int NUM_DIGITS_OUTPUT = 6;

	private static final String blockOfZeros;

	static {
		char[] chars = new char[NUM_DIGITS_OUTPUT];
		for (int i = 0; i < chars.length; i++) {
			chars[i] = '0';
		}
		blockOfZeros = new String(chars);
	}

	/**
	 * Generate and return a 16-character secret key in base32 format (A-Z2-7) using {@link SecureRandom}. Could be used
	 * to generate the QR image to be shared with the user. Other lengths should use {@link #generateBase32Secret(int)}.
	 */
	public static String generateBase32Secret() {
		return generateBase32Secret(16);
	}

	/**
	 * Similar to {@link #generateBase32Secret()} but specifies a character length.
	 */
	public static String generateBase32Secret(int length) {
		StringBuilder sb = new StringBuilder(length);
		Random random = new SecureRandom();
		for (int i = 0; i < length; i++) {
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
	 * Validate a given secret-number using the secret base-32 string. This allows you to set a window in seconds to
	 * account for people being close to the end of the time-step. For example, if windowSeconds is 10 then this method
	 * will check the authNumber against the generated number from 10 seconds before now through 10 seconds after now.
	 * 
	 * <p>
	 * WARNING: This requires a system clock that is in sync with the world.
	 * </p>
	 * 
	 * @param base32Secret
	 *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
	 * @param authNumber
	 *            Time based number provided by the user from their authenticator application.
	 * @param windowMillis
	 *            Number of milliseconds that they are allowed to be off and still match. This checks before and after
	 *            the current time to account for clock variance. Set to 0 for no window.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, int windowMillis)
			throws GeneralSecurityException {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, System.currentTimeMillis(),
				DEFAULT_TIME_STEP_SECONDS);
	}

	/**
	 * Similar to {@link #validateCurrentNumber(String, int, int)} except exposes other parameters. Mostly for testing.
	 * 
	 * @param base32Secret
	 *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
	 * @param authNumber
	 *            Time based number provided by the user from their authenticator application.
	 * @param windowMillis
	 *            Number of milliseconds that they are allowed to be off and still match. This checks before and after
	 *            the current time to account for clock variance. Set to 0 for no window.
	 * @param timeMillis
	 *            Time in milliseconds.
	 * @param timeStepSeconds
	 *            Time step in seconds. The default value is 30 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, int windowMillis, long timeMillis,
			int timeStepSeconds) throws GeneralSecurityException {
		long from = timeMillis;
		long to = timeMillis;
		if (windowMillis > 0) {
			from -= windowMillis;
			to += windowMillis;
		}
		long timeStepMillis = timeStepSeconds * 1000;
		for (long millis = from; millis <= to; millis += timeStepMillis) {
			long compare = generateNumber(base32Secret, millis, timeStepSeconds);
			if (compare == authNumber) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Return the current number to be checked. This can be compared against user input.
	 * 
	 * <p>
	 * WARNING: This requires a system clock that is in sync with the world.
	 * </p>
	 * 
	 * @param base32Secret
	 *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateCurrentNumberString(String base32Secret) throws GeneralSecurityException {
		return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String)} except exposes other parameters. Mostly for testing.
	 * 
	 * @param base32Secret
	 *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
	 * @param timeMillis
	 *            Time in milliseconds.
	 * @param timeStepSeconds
	 *            Time step in seconds. The default value is 30 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateNumberString(String base32Secret, long timeMillis, int timeStepSeconds)
			throws GeneralSecurityException {
		long number = generateNumber(base32Secret, timeMillis, timeStepSeconds);
		return zeroPrepend(number, NUM_DIGITS_OUTPUT);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String)} but this returns a long instead of a string.
	 * 
	 * @return A number which should match the user's authenticator application output.
	 */
	public static long generateCurrentNumber(String base32Secret) throws GeneralSecurityException {
		return generateNumber(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS);
	}

	/**
	 * Similar to {@link #generateNumberString(String, long, int)} but this returns a long instead of a string.
	 * 
	 * @return A number which should match the user's authenticator application output.
	 */
	public static long generateNumber(String base32Secret, long timeMillis, int timeStepSeconds)
			throws GeneralSecurityException {

		byte[] key = decodeBase32(base32Secret);

		byte[] data = new byte[8];
		long value = timeMillis / 1000 / timeStepSeconds;
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

		return truncatedHash;
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program
	 * as an easy way to enter the secret.
	 * 
	 * <p>
	 * NOTE: the returned URL should be escaped if it is to be put into a href on a web-page.
	 * </p>
	 * 
	 * @param keyId
	 *            Name of the key that you want to show up in the users authentication application. Should already be
	 *            URL encoded.
	 * @param secret
	 *            Secret string that will be used when generating the current number.
	 */
	public static String qrImageUrl(String keyId, String secret) {
		StringBuilder sb = new StringBuilder(128);
		sb.append("https://chart.googleapis.com/chart");
		sb.append("?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=");
		sb.append("otpauth://totp/").append(keyId).append("%3Fsecret%3D").append(secret);
		return sb.toString();
	}

	/**
	 * Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
	 */
	static String zeroPrepend(long num, int digits) {
		String numStr = Long.toString(num);
		if (numStr.length() >= digits) {
			return numStr;
		} else {
			StringBuilder sb = new StringBuilder(digits);
			int zeroCount = digits - numStr.length();
			sb.append(blockOfZeros, 0, zeroCount);
			sb.append(numStr);
			return sb.toString();
		}
	}

	/**
	 * Decode base-32 method. I didn't want to add a dependency to Apache Codec just for this decode method. Exposed for
	 * testing.
	 */
	static byte[] decodeBase32(String str) {
		// each base-32 character encodes 5 bits
		int numBytes = ((str.length() * 5) + 7) / 8;
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
				case 0:
					// all 5 bits is top 5 bits
					working = (val & 0x1F) << 3;
					which = 1;
					break;
				case 1:
					// top 3 bits is lower 3 bits
					working |= (val & 0x1C) >> 2;
					result[resultIndex++] = (byte) working;
					// lower 2 bits is upper 2 bits
					working = (val & 0x03) << 6;
					which = 2;
					break;
				case 2:
					// all 5 bits is mid 5 bits
					working |= (val & 0x1F) << 1;
					which = 3;
					break;
				case 3:
					// top 1 bit is lowest 1 bit
					working |= (val & 0x10) >> 4;
					result[resultIndex++] = (byte) working;
					// lower 4 bits is top 4 bits
					working = (val & 0x0F) << 4;
					which = 4;
					break;
				case 4:
					// top 4 bits is lowest 4 bits
					working |= (val & 0x1E) >> 1;
					result[resultIndex++] = (byte) working;
					// lower 1 bit is top 1 bit
					working = (val & 0x01) << 7;
					which = 5;
					break;
				case 5:
					// all 5 bits is mid 5 bits
					working |= (val & 0x1F) << 2;
					which = 6;
					break;
				case 6:
					// top 2 bits is lowest 2 bits
					working |= (val & 0x18) >> 3;
					result[resultIndex++] = (byte) working;
					// lower 3 bits of byte 6 is top 3 bits
					working = (val & 0x07) << 5;
					which = 7;
					break;
				case 7:
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
