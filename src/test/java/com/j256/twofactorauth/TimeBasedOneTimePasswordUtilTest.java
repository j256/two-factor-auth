package com.j256.twofactorauth;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.Random;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class TimeBasedOneTimePasswordUtilTest {

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
	public void testDecodeHexadecimal() throws DecoderException {
		Random random = new Random();
		random.nextBytes(new byte[100]);
		for (int i = 0; i < 10000; i++) {
			byte[] bytes = new byte[random.nextInt(10) + 1];
			random.nextBytes(bytes);
			String encoded = Hex.encodeHexString(bytes);
			byte[] expected = Hex.decodeHex(encoded.toCharArray());
			byte[] actual = TimeBasedOneTimePasswordUtil.decodeHex(encoded);
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

		testStringAndNumber(secret, 7451000L, 3, "3", 1);
		testStringAndNumber(secret, 7451000L, 93, "93", 2);
		testStringAndNumber(secret, 7451000L, 893, "893", 3);
		testStringAndNumber(secret, 7451000L, 5893, "5893", 4);
		testStringAndNumber(secret, 7451000L, 25893, "25893", 5);
		testStringAndNumber(secret, 7451000L, 325893, "325893", 6);
		testStringAndNumber(secret, 7451000L, 9325893, "9325893", 7);
		testStringAndNumber(secret, 7451000L, 89325893, "89325893", 8);

		testStringAndNumber(secret, 1000L, 34748810, "34748810", 8);
		testStringAndNumber(secret, 7451000L, 89325893, "89325893", 8);
		testStringAndNumber(secret, 15451000L, 67064088, "67064088", 8);
		testStringAndNumber(secret, 5964551130L, 5993908, "05993908", 8);
		testStringAndNumber(secret, 348402049542546145L, 26009637, "26009637", 8);
		testStringAndNumber(secret, 2049455124374752571L, 94000743, "94000743", 8);
		testStringAndNumber(secret, 1359002349304873750L, 86000092, "86000092", 8);
		testStringAndNumber(secret, 6344447817348357059L, 80000007, "80000007", 8);
		testStringAndNumber(secret, 2125701285964551130L, 24000000, "24000000", 8);
	}

	private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString)
			throws GeneralSecurityException {
		testStringAndNumber(secret, timeMillis, expectedNumber, expectedString,
				TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH);
	}

	private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString,
			int length) throws GeneralSecurityException {
		String str = TimeBasedOneTimePasswordUtil.generateNumberString(secret, timeMillis,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS, length);
		assertEquals(length, str.length());
		assertEquals(expectedString, str);
		assertEquals("expected numbers to match", expectedNumber, TimeBasedOneTimePasswordUtil.generateNumber(secret,
				timeMillis, TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS, length));
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

	@Test
	public void testWindow() throws GeneralSecurityException {
		String secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		long window = 10000;
		Random random = new Random();
		for (int i = 0; i < 1000; i++) {
			long now = random.nextLong();
			if (now < 0) {
				now = -now;
			}
			int number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		}
	}

	@Test
	public void testWindowStuff() throws GeneralSecurityException {
		String secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		long window = 10000;
		long now = 5462669356666716002L;
		int number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		now = 8835485943423840000L;
		number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window - 1,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		now = 8363681401523009999L;
		number = TimeBasedOneTimePasswordUtil.generateNumber(secret, now,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now - window,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertFalse(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, window, now + window + 1,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
	}

	@Test
	public void testHexWindow() throws GeneralSecurityException {
		String hexSecret = TimeBasedOneTimePasswordUtil.generateHexSecret();
		long window = 10000;
		Random random = new Random();
		for (int i = 0; i < 1000; i++) {
			long now = random.nextLong();
			if (now < 0) {
				now = -now;
			}
			int number = TimeBasedOneTimePasswordUtil.generateNumberHex(hexSecret, now,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumberHex(hexSecret, number, window, now - window,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumberHex(hexSecret, number, window, now,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
			assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumberHex(hexSecret, number, window, now + window,
					TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		}
	}

	@Test
	public void testCoverage() throws GeneralSecurityException {
		String secret = "ny4A5CPJZ46LXZCP";
		TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, 948323, 15000);
		assertEquals(TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH,
				TimeBasedOneTimePasswordUtil.generateCurrentNumberString(secret).length());

		int number = TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret);
		assertTrue(TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, number, 0, System.currentTimeMillis(),
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));

		int len = 3;
		assertEquals(len, TimeBasedOneTimePasswordUtil.generateCurrentNumberString(secret, len).length());
		int num = TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret);
		assertTrue(num >= 0 && num < 1000000);
		num = TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 3);
		assertTrue(num >= 0 && num < 1000);
		assertNotNull(TimeBasedOneTimePasswordUtil.generateOtpAuthUrl("key", secret));
		assertNotNull(TimeBasedOneTimePasswordUtil.generateOtpAuthUrl("key", secret, 8));
		assertNotNull(TimeBasedOneTimePasswordUtil.qrImageUrl("key", secret));
		assertNotNull(TimeBasedOneTimePasswordUtil.qrImageUrl("key", secret, 3));
		assertNotNull(TimeBasedOneTimePasswordUtil.qrImageUrl("key", secret, 3, 500));

		String hexSecret = "0123456789abcdefABCDEF";
		num = TimeBasedOneTimePasswordUtil.generateCurrentNumberHex(hexSecret);
		assertTrue(num >= 0 && num < 1000000);
		num = TimeBasedOneTimePasswordUtil.generateCurrentNumberHex(hexSecret, 3);
		assertTrue(num >= 0 && num < 1000);
		TimeBasedOneTimePasswordUtil.validateCurrentNumberHex(hexSecret, num, 0);
		assertNotNull(TimeBasedOneTimePasswordUtil.generateCurrentNumberStringHex(hexSecret));
		assertNotNull(TimeBasedOneTimePasswordUtil.generateCurrentNumberStringHex(hexSecret, 3));
		TimeBasedOneTimePasswordUtil.decodeHex("01234");

		try {
			TimeBasedOneTimePasswordUtil.generateCurrentNumber(".");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}
		try {
			TimeBasedOneTimePasswordUtil.generateCurrentNumber("^");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeBase32("0");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeBase32("/");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeBase32("^");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeBase32("~");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeHex("z");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeHex("/");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeHex("^");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			TimeBasedOneTimePasswordUtil.decodeHex("~");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}
	}
}
