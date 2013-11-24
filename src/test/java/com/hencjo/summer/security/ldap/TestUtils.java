package com.hencjo.summer.security.ldap;

import com.hencjo.summer.security.ldap.utils.Hex;

public class TestUtils {
	public static String readable(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(Hex.prettyByte(b) + ":");
		}
		sb.setLength(sb.length() - 1);
		return sb.toString();
	}
}
