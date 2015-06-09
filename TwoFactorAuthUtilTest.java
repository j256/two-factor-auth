package com.j256.common.utils;

/**
 * Little test program to show how to use the utility class.
 */
public class TwoFactorAuthUtilTest {

	public static void main(String[] args) throws Exception {
		new TwoFactorAuthUtilTest().doMain();
	}

	private void doMain() throws Exception {

		TwoFactorAuthUtil twoFactorAuthUtil = new TwoFactorAuthUtil();

		// String base32Secret = generateBase32Secret();
		String base32Secret = "NY4A5CPJZ46LXZCP";

		System.out.println("secret = " + base32Secret);

		// this is the name of the key which can be displayed by the authenticator program
		String keyId = "user@foo.com";
		System.out.println("Image url = " + twoFactorAuthUtil.qrImageUrl(keyId, base32Secret));
		// we can display this image to the user to let them load it into their auth program

		// we can use the code here and compare it against user input
		String code = twoFactorAuthUtil.generateCurrentNumber(base32Secret);

		/*
		 * this little loop is here to show how the number changes over time
		 */
		while (true) {
			long diff =
					TwoFactorAuthUtil.TIME_STEP_SECONDS
							- ((System.currentTimeMillis() / 1000) % TwoFactorAuthUtil.TIME_STEP_SECONDS);
			code = twoFactorAuthUtil.generateCurrentNumber(base32Secret);
			System.out.println("Secret code = " + code + ", change in " + diff + " seconds");
			Thread.sleep(1000);
		}
	}
}
