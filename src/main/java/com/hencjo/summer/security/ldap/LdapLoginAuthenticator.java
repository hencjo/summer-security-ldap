package com.hencjo.summer.security.ldap;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import com.hencjo.summer.security.ldap.LdapMessages.BindResponse;
import com.hencjo.summer.security.ldap.LdapMessages.UnbindRequest;

public class LdapLoginAuthenticator {
	public boolean attemptLogin(String hostname, int port, String username, String password) throws IOException, DerDecodeException, UnknownHostException {
		try (Socket s = new Socket(hostname, port); InputStream inputStream = s.getInputStream(); OutputStream outputStream = s.getOutputStream()) {
			outputStream.write(LdapLoginAuthenticator.bindRequest(username, password).message.der());
	
			BindResponse bindResponse = new BindResponse();
			bindResponse.message.decode(inputStream);
	
			try {
				return (bindResponse.resultCode.get() == 0);
			} finally {
				outputStream.write(LdapLoginAuthenticator.unbindRequest().message.der());
			}
		}
	}

	private static UnbindRequest unbindRequest() {
		UnbindRequest unbindRequest = new LdapMessages.UnbindRequest();
		unbindRequest.messageId.set(2);
		return unbindRequest;
	}

	private static LdapMessages.BindRequest bindRequest(String username, String password) {
		LdapMessages.BindRequest request = new LdapMessages.BindRequest();
		request.messageId.set(1);
		request.protocolVersion.set(3);
		request.username.set(username);
		request.password.set(password.getBytes(Charset.forName("UTF-8")));
		return request;
	}
}