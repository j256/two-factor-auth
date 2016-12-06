package com.j256.twofactorauth;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

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
	public void testVariusKnownSecretTimeCodes() throws GeneralSecurityException {
		String secret = "NY4A5CPJZ46LXZCP";
		assertEquals("748810", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 1000L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("325893", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 7451000L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("064088", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 15451000L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("009637", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 348402049542546145L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("000743", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 2049455124374752571L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("000092", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 1359002349304873750L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("000007", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 6344447817348357059L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
		assertEquals("000000", TimeBasedOneTimePasswordUtil.generateCurrentNumber(secret, 2125701285964551130L,
				TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS));
	}
}
