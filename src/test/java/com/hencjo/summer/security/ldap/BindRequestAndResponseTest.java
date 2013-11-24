package com.hencjo.summer.security.ldap;

import static org.junit.Assert.*;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import org.junit.Test;
import com.hencjo.summer.security.ldap.LdapMessages.BindResponse;

import static com.hencjo.summer.security.ldap.TestUtils.*;

public class BindRequestAndResponseTest {
	@Test
	public void testDerEncodeBindRequest() {
		LdapMessages.BindRequest request = new LdapMessages.BindRequest();
		request.messageId.set(1);
		request.protocolVersion.set(3);
		request.username.set("username");
		request.password.set("password".getBytes(Charset.forName("UTF-8")));

		assertEquals("30:22:02:04:00:00:00:01:60:1a:02:04:00:00:00:03:04:08:75:73:65:72:6e:61:6d:65:80:08:70:61:73:73:77:6f:72:64", readable(request.message.der()));
	}
	
	
	@Test
	public void testDecodeBindResponse() throws Exception {
		{
			BindResponse bindResponse = new LdapMessages.BindResponse();
			bindResponse.message.decode(fakeInput("30:84:00:00:00:10:02:01:01:61:84:00:00:00:07:0a:01:00:04:00:04:00"));

			assertEquals(1, bindResponse.messageId.get());
			assertEquals(0, bindResponse.resultCode.get());
			assertEquals("", bindResponse.matchedDn.get());
			assertEquals("", bindResponse.diagnosticMessage.get());
		}
		
		
		{
			BindResponse bindResponse = new LdapMessages.BindResponse();
			bindResponse.message.decode(fakeInput("30:84:00:00:00:67:02:01:01:61:84:00:00:00:5e:0a:01:31:04:00:04:57:38:30:30:39:30:33:30:38:3a:20:4c:64:61:70:45:72:72:3a:20:44:53:49:44:2d:30:43:30:39:30:33:33:34:2c:20:63:6f:6d:6d:65:6e:74:3a:20:41:63:63:65:70:74:53:65:63:75:72:69:74:79:43:6f:6e:74:65:78:74:20:65:72:72:6f:72:2c:20:64:61:74:61:20:35:32:65:2c:20:76:65:63:65:00"));

			assertEquals(1, bindResponse.messageId.get());
			assertEquals(49, bindResponse.resultCode.get());
			assertEquals("", bindResponse.matchedDn.get());
			assertEquals("80090308: LdapErr: DSID-0C090334, comment: AcceptSecurityContext error, data 52e, vece\0", bindResponse.diagnosticMessage.get());
		}
	}

	private static ByteArrayInputStream fakeInput(String success) {
		byte[] replace = hexStringToByteArray(success.replace(":", ""));
		return new ByteArrayInputStream(replace);
	}
	
	
	public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
	}
}
