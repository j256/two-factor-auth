package com.j256.twofactorauth;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementation of the Time-based One-Time Password (TOTP) two factor authentication algorithm. You need to:
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
 * For more details about this magic algorithm, see: http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
 * </p>
 * 
 * @author graywatson
 */
public class TimeBasedOneTimePasswordUtil {

	/** default time-step which is part of the spec, 30 seconds is default */
	public static final int DEFAULT_TIME_STEP_SECONDS = 30;
	/** default number of digits in a OTP string */
	public static int DEFAULT_OTP_LENGTH = 6;
	/** default hight/width of QR image */
	public static int DEFAULT_QR_DIMENTION = 200;
	/** set to the number of digits to control 0 prefix, set to 0 for no prefix */
	private static int MAX_NUM_DIGITS_OUTPUT = 100;

	private static final String blockOfZeros;

	static {
		char[] chars = new char[MAX_NUM_DIGITS_OUTPUT];
		Arrays.fill(chars, '0');
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
	public static String generateBase32Secret(int numDigits) {
		StringBuilder sb = new StringBuilder(numDigits);
		Random random = new SecureRandom();
		for (int i = 0; i < numDigits; i++) {
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
	 * Generate and return a 32-character secret key in hexadecimal format (0-9A-F) using {@link SecureRandom}. Could be
	 * used to generate the QR image to be shared with the user. Other lengths should use
	 * {@link #generateHexSecret(int)}.
	 */
	public static String generateHexSecret() {
		return generateHexSecret(32);
	}

	/**
	 * Similar to {@link #generateHexSecret()} but specifies a character length.
	 */
	public static String generateHexSecret(int numDigits) {
		StringBuilder sb = new StringBuilder(numDigits);
		Random random = new SecureRandom();
		for (int i = 0; i < numDigits; i++) {
			int val = random.nextInt(16);
			if (val < 10) {
				sb.append((char) ('0' + val));
			} else {
				sb.append((char) ('A' + (val - 10)));
			}
		}
		return sb.toString();
	}

	/**
	 * Validate a given secret-number using the secret base-32 string. This allows you to set a window in milliseconds
	 * to account for people being close to the end of the time-step. For example, if windowMillis is 10000 then this
	 * method will check the authNumber against the generated number from 10 seconds before now through 10 seconds after
	 * now.
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
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis)
			throws GeneralSecurityException {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, System.currentTimeMillis(),
				DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #validateCurrentNumber(String, int, long)} except it uses a hexadecimal secret instead of
	 * base-32.
	 * 
	 * @param hexSecret
	 *            Secret string encoded in hexadecimal that was used to generate the QR code or shared with the user.
	 * @param authNumber
	 *            Time based number provided by the user from their authenticator application.
	 * @param windowMillis
	 *            Number of milliseconds that they are allowed to be off and still match. This checks before and after
	 *            the current time to account for clock variance. Set to 0 for no window.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumberHex(String hexSecret, int authNumber, long windowMillis)
			throws GeneralSecurityException {
		return validateCurrentNumberHex(hexSecret, authNumber, windowMillis, System.currentTimeMillis(),
				DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
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
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds) throws GeneralSecurityException {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, timeMillis, timeStepSeconds,
				DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #validateCurrentNumberHex(String, int, int)} except exposes other parameters. Mostly for
	 * testing.
	 * 
	 * @param hexSecret
	 *            Secret string encoded in hexadecimal that was used to generate the QR code or shared with the user.
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
	public static boolean validateCurrentNumberHex(String hexSecret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds) throws GeneralSecurityException {
		return validateCurrentNumberHex(hexSecret, authNumber, windowMillis, timeMillis, timeStepSeconds,
				DEFAULT_OTP_LENGTH);
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
	 * @param numDigits
	 *            The number of digits of the OTP.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds, int numDigits) throws GeneralSecurityException {
		byte[] key = decodeBase32(base32Secret);
		return validateCurrentNumber(key, authNumber, windowMillis, timeMillis, timeStepSeconds, numDigits);
	}

	/**
	 * Similar to {@link #validateCurrentNumber(String, int, long, long, int, int)} except it uses hexadecimal secret
	 * instead of base-32.
	 * 
	 * @param hexSecret
	 *            Secret string encoded in hexadecimal that was used to generate the QR code or shared with the user.
	 * @param authNumber
	 *            Time based number provided by the user from their authenticator application.
	 * @param windowMillis
	 *            Number of milliseconds that they are allowed to be off and still match. This checks before and after
	 *            the current time to account for clock variance. Set to 0 for no window.
	 * @param timeMillis
	 *            Time in milliseconds.
	 * @param timeStepSeconds
	 *            Time step in seconds. The default value is 30 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
	 * @param numDigits
	 *            The number of digits of the OTP.
	 * @return True if the authNumber matched the calculated number within the specified window.
	 */
	public static boolean validateCurrentNumberHex(String hexSecret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds, int numDigits) throws GeneralSecurityException {
		byte[] key = decodeHex(hexSecret);
		return validateCurrentNumber(key, authNumber, windowMillis, timeMillis, timeStepSeconds, numDigits);
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
		return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS,
				DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String)} except this uses a hexadecimal secret.
	 * 
	 * @param hexSecret
	 *            Secret string encoded in hexadecimal that was used to generate the QR code or shared with the user.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateCurrentNumberStringHex(String hexSecret) throws GeneralSecurityException {
		return generateNumberStringHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS,
				DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String, int)} but you specify the number of digits.
	 *
	 * @param base32Secret
	 *            Secret string encoded using base-32 that was used to generate the QR code or shared with the user.
	 * @param numDigits
	 *            The number of digits of the OTP.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateCurrentNumberString(String base32Secret, int numDigits)
			throws GeneralSecurityException {
		return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, numDigits);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String, int)} but you specify the number of digits.
	 *
	 * @param hexSecret
	 *            Secret string encoded in hexadecimal that was used to generate the QR code or shared with the user.
	 * @param numDigits
	 *            The number of digits of the OTP.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateCurrentNumberStringHex(String hexSecret, int numDigits)
			throws GeneralSecurityException {
		return generateNumberStringHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, numDigits);
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
	 * @param numDigits
	 *            The number of digits of the OTP.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateNumberString(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		int number = generateNumber(base32Secret, timeMillis, timeStepSeconds, numDigits);
		return zeroPrepend(number, numDigits);
	}

	/**
	 * Similar to {@link #generateNumberStringHex(String, long, int, int)} except it uses a hexadecimal secret.
	 * 
	 * @param hexSecret
	 *            Secret string encoded in hexadecimal that was used to generate the QR code or shared with the user.
	 * @param timeMillis
	 *            Time in milliseconds.
	 * @param timeStepSeconds
	 *            Time step in seconds. The default value is 30 seconds here. See {@link #DEFAULT_TIME_STEP_SECONDS}.
	 * @param numDigits
	 *            The number of digits of the OTP.
	 * @return A number as a string with possible leading zeros which should match the user's authenticator application
	 *         output.
	 */
	public static String generateNumberStringHex(String hexSecret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		int number = generateNumberHex(hexSecret, timeMillis, timeStepSeconds, numDigits);
		return zeroPrepend(number, numDigits);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String)} but this returns a int instead of a string.
	 * 
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateCurrentNumber(String base32Secret) throws GeneralSecurityException {
		return generateNumber(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateCurrentNumberStringHex(String)} but this returns a int instead of a string.
	 * 
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateCurrentNumberHex(String hexSecret) throws GeneralSecurityException {
		return generateNumberHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateCurrentNumberString(String, int)} but this returns a int instead of a string.
	 *
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateCurrentNumber(String base32Secret, int numDigits) throws GeneralSecurityException {
		return generateNumber(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, numDigits);
	}

	/**
	 * Similar to {@link #generateCurrentNumberStringHex(String, int)} but this returns a int instead of a string.
	 *
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateCurrentNumberHex(String hexSecret, int numDigits) throws GeneralSecurityException {
		return generateNumberHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, numDigits);
	}

	/**
	 * Similar to {@link #generateNumberString(String, long, int, int)} but this returns a int instead of a string.
	 * 
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds)
			throws GeneralSecurityException {
		return generateNumber(base32Secret, timeMillis, timeStepSeconds, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateNumberStringHex(String, long, int, int))} but this returns a int instead of a string.
	 * 
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateNumberHex(String hexSecret, long timeMillis, int timeStepSeconds)
			throws GeneralSecurityException {
		return generateNumberHex(hexSecret, timeMillis, timeStepSeconds, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Similar to {@link #generateNumberString(String, long, int)} but this returns a int instead of a string.
	 *
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		long value = generateValue(timeMillis, timeStepSeconds);
		byte[] key = decodeBase32(base32Secret);
		return generateNumberFromKeyValue(key, value, numDigits);
	}

	/**
	 * Similar to {@link #generateNumber(String, long, int, int)} but with a hexadecimal secret.
	 *
	 * @return A number which should match the user's authenticator application output.
	 */
	public static int generateNumberHex(String hexSecret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		long value = generateValue(timeMillis, timeStepSeconds);
		byte[] key = decodeHex(hexSecret);
		return generateNumberFromKeyValue(key, value, numDigits);
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program
	 * as an easy way to enter the secret.
	 * 
	 * @param keyId
	 *            Name of the key that you want to show up in the users authentication application. Should already be
	 *            URL encoded.
	 * @param secret
	 *            Secret string that will be used when generating the current number.
	 */
	public static String qrImageUrl(String keyId, String secret) {
		return qrImageUrl(keyId, secret, DEFAULT_OTP_LENGTH, DEFAULT_QR_DIMENTION);
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program
	 * as an easy way to enter the secret.
	 *
	 * @param keyId
	 *            Name of the key that you want to show up in the users authentication application. Should already be
	 *            URL encoded.
	 * @param secret
	 *            Secret string that will be used when generating the current number.
	 * @param numDigits
	 *            The number of digits of the OTP.
	 */
	public static String qrImageUrl(String keyId, String secret, int numDigits) {
		return qrImageUrl(keyId, secret, numDigits, DEFAULT_QR_DIMENTION);
	}

	/**
	 * Return the QR image url thanks to Google. This can be shown to the user and scanned by the authenticator program
	 * as an easy way to enter the secret.
	 * 
	 * @param keyId
	 *            Name of the key that you want to show up in the users authentication application. Should already be
	 *            URL encoded.
	 * @param secret
	 *            Secret string that will be used when generating the current number.
	 * @param numDigits
	 *            The number of digits of the OTP. Can be set to {@link #DEFAULT_OTP_LENGTH}.
	 * @param imageDimension
	 *            The dimension of the image, width and height. Can be set to {@link #DEFAULT_QR_DIMENTION}.
	 */
	public static String qrImageUrl(String keyId, String secret, int numDigits, int imageDimension) {
		StringBuilder sb = new StringBuilder(128);
		sb.append("https://chart.googleapis.com/chart?chs=" + imageDimension + "x" + imageDimension + "&cht=qr&chl="
				+ imageDimension + "x" + imageDimension + "&chld=M|0&cht=qr&chl=");
		addOtpAuthPart(keyId, secret, sb, numDigits);
		return sb.toString();
	}

	/**
	 * Return the otp-auth part of the QR image which is suitable to be injected into other QR generators (e.g. JS
	 * generator).
	 *
	 * @param keyId
	 *            Name of the key that you want to show up in the users authentication application. Should already be
	 *            URL encoded.
	 * @param secret
	 *            Secret string that will be used when generating the current number.
	 */
	public static String generateOtpAuthUrl(String keyId, String secret) {
		return generateOtpAuthUrl(keyId, secret, DEFAULT_OTP_LENGTH);
	}

	/**
	 * Return the otp-auth part of the QR image which is suitable to be injected into other QR generators (e.g. JS
	 * generator).
	 *
	 * @param keyId
	 *            Name of the key that you want to show up in the users authentication application. Should already be
	 *            URL encoded.
	 * @param secret
	 *            Secret string that will be used when generating the current number.
	 * @param numDigits
	 *            The number of digits" of the OTP.
	 */
	public static String generateOtpAuthUrl(String keyId, String secret, int numDigits) {
		StringBuilder sb = new StringBuilder(128);
		addOtpAuthPart(keyId, secret, sb, numDigits);
		return sb.toString();
	}

	private static void addOtpAuthPart(String keyId, String secret, StringBuilder sb, int numDigits) {
		sb.append("otpauth://totp/")
				.append(keyId)
				.append("%3Fsecret%3D")
				.append(secret)
				.append("%26digits%3D")
				.append(numDigits);
	}

	private static boolean validateCurrentNumber(byte[] key, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds, int numDigits) throws GeneralSecurityException {
		if (windowMillis <= 0) {
			// just test the current time
			long value = generateValue(timeMillis, timeStepSeconds);
			long generatedNumber = generateNumberFromKeyValue(key, value, numDigits);
			return (generatedNumber == authNumber);
		}
		// maybe check multiple values
		long startValue = generateValue(timeMillis - windowMillis, timeStepSeconds);
		long endValue = generateValue(timeMillis + windowMillis, timeStepSeconds);
		for (long value = startValue; value <= endValue; value++) {
			long generatedNumber = generateNumberFromKeyValue(key, value, numDigits);
			if (generatedNumber == authNumber) {
				return true;
			}
		}
		return false;
	}

	private static long generateValue(long timeMillis, int timeStepSeconds) {
		return timeMillis / 1000 / timeStepSeconds;
	}

	private static int generateNumberFromKeyValue(byte[] key, long value, int numDigits)
			throws GeneralSecurityException {

		byte[] data = new byte[8];
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

		// the token is then the last <length> digits in the number
		long mask = 1;
		for (int i = 0; i < numDigits; i++) {
			mask *= 10;
		}
		truncatedHash %= mask;
		return (int) truncatedHash;
	}

	/**
	 * Return the string prepended with 0s. Tested as 10x faster than String.format("%06d", ...); Exposed for testing.
	 */
	static String zeroPrepend(int num, int digits) {
		String numStr = Integer.toString(num);
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
	 * Decode base-32 string. I didn't want to add a dependency to Apache Codec just for this decode method. Exposed for
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

	/**
	 * Decode hexadecimal string method. I didn't want to add a dependency to Apache Codec just for this decode method.
	 * Exposed for testing.
	 */
	static byte[] decodeHex(String str) {
		// each hex character encodes 4 bits
		int numBytes = ((str.length() * 4) + 7) / 8;
		byte[] result = new byte[numBytes];
		int resultIndex = 0;
		int which = 0;
		int working = 0;
		for (int i = 0; i < str.length(); i++) {
			char ch = str.charAt(i);
			int val;
			if (ch >= '0' && ch <= '9') {
				val = (ch - '0');
			} else if (ch >= 'a' && ch <= 'f') {
				val = 10 + (ch - 'a');
			} else if (ch >= 'A' && ch <= 'F') {
				val = 10 + (ch - 'A');
			} else {
				throw new IllegalArgumentException("Invalid hex character: " + ch);
			}
			/*
			 * There are probably better ways to do this but this seemed the most straightforward.
			 */
			if (which == 0) {
				// top 4 bits
				working = (val & 0xF) << 4;
				which = 1;
			} else {
				// lower 4 bits
				working |= (val & 0xF);
				result[resultIndex++] = (byte) working;
				which = 0;
			}
		}
		if (which != 0) {
			result[resultIndex++] = (byte) (working >> 4);
		}
		if (resultIndex != result.length) {
			// may not happen but let's be careful out there
			result = Arrays.copyOf(result, resultIndex);
		}
		return result;
	}
}
