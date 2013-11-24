package com.hencjo.summer.security.ldap.utils;

public class Hex {

	public static String prettyByte(byte read) {
		String hexString = Integer.toHexString(read & 0xFF);
		if (hexString.length() < 2) return "0" + hexString;
		return hexString;
	}

}
