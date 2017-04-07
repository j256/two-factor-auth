package com.j256.twofactorauth;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.util.Random;

import org.apache.commons.codec.binary.Base32;
import org.junit.Test;

public class TwoFactorAuthUtilTest {

	@Test
	public void testZeroPrepend() {
		Random random = new Random();
		for (int i = 0; i < 10000; i++) {
			int num = random.nextInt(1000000);
			/**
			 * NOTE: Did a speed test of these and the zeroPrepend is ~13x faster.
			 */
			assertEquals(String.format("%06d", num), TimeBasedOneTimePasswordUtil.zeroPrepend(num, 6));
		}
	}

	@Test
	public void testDecodeBase32() {
		Random random = new Random();
		random.nextBytes(new byte[100]);
		Base32 base32 = new Base32();
		for (int i = 0; i < 10000; i++) {
			byte[] bytes = new byte[random.nextInt(10) + 1];
			random.nextBytes(bytes);
			String encoded = base32.encodeAsString(bytes);
			byte[] expected = base32.decode(encoded);
			byte[] actual = TimeBasedOneTimePasswordUtil.decodeBase32(encoded);
			assertArrayEquals(expected, actual);
		}
	}

	@Test
	public void testBadBase32() {
		String[] strings =
				new String[] { "A", "AB", "ABC", "ABCD", "ABCDE", "ABCDEF", "ABCDEFG", "ABCDEFGH", "ABCDEFGHI" };
		Base32 base32 = new Base32();
		for (String str : strings) {
			byte[] decoded = TimeBasedOneTimePasswordUtil.decodeBase32(str);
			String encoded = base32.encodeAsString(decoded);
			byte[] result = TimeBasedOneTimePasswordUtil.decodeBase32(encoded);
			// System.out.println(str + " becomes " + encoded);
			assertArrayEquals(decoded, result);
		}
	}

	@Test
	public void testVariusKnownSecretTimeCodes() throws GeneralSecurityException {
		String secret = "NY4A5CPJZ46LXZCP";
		testStringAndNumber(secret, 1000L, 748810, "748810");
		testStringAndNumber(secret, 7451000L, 325893, "325893");
		testStringAndNumber(secret, 15451000L, 64088, "064088");
		testStringAndNumber(secret, 348402049542546145L, 9637, "009637");
		testStringAndNumber(secret, 2049455124374752571L, 743, "000743");
		testStringAndNumber(secret, 1359002349304873750L, 92, "000092");
		testStringAndNumber(secret, 6344447817348357059L, 7, "000007");
		testStringAndNumber(secret, 2125701285964551130L, 0, "000000");
	}

	private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString)
			throws GeneralSecurityException {
		assertEquals(expectedString, TimeBasedOneTimePasswordUtil.generateNumberString(secret, timeMillis,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals(expectedNumber, TimeBasedOneTimePasswordUtil.generateNumber(secret, timeMillis,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
	}

	@Test
	public void testValidate() throws GeneralSecurityException {
		String secret = "NY4A5CPJZ46LXZCP";
		assertEquals(162123, TimeBasedOneTimePasswordUtil.generateNumber(secret, 7439999,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 325893, 0, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 0, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		// this should of course match
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 325893, 15000, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		/*
		 * Test upper window which starts +15000 milliseconds.
		 */

		// but this is the next value and the window doesn't quite take us to the next time-step
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 14999, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		// but this is the next value which is 15000 milliseconds ahead
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 15000, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		/*
		 * The lower window is less than -15000 milliseconds so we have to test a window of 15001.
		 */

		// but this is the previous value and the window doesn't quite take us to the previous time-step
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 287511, 15000, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		// but this is the previous value which is 15001 milliseconds earlier
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 162123, 15001, 7455000,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
	}

	@Test
	public void testGenerateSecret() {
		assertEquals(16, TimeBasedOneTimePasswordUtil.generateBase32Secret().length());
		assertEquals(16, TimeBasedOneTimePasswordUtil.generateBase32Secret(16).length());
		assertEquals(1, TimeBasedOneTimePasswordUtil.generateBase32Secret(1).length());
	}
}
