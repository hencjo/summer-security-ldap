package com.hencjo.summer.security.ldap;

import static com.hencjo.summer.security.ldap.asn.ASN.*;

public class LdapMessages {
	public static final class BindResponse {
		public final AsnInteger messageId = integer();
		public final AsnEnumerated resultCode = enumerated();
		public final AsnString matchedDn = string();
		public final AsnString diagnosticMessage = string();
		public final AsnSequence message = sequence(messageId, application(1, resultCode, matchedDn, diagnosticMessage));
	}

	public static final class BindRequest {
		public final AsnInteger messageId = integer();
		public final AsnInteger protocolVersion = integer();
		public final AsnString username = string();
		public final AsnRaw password = raw();
		public final AsnSequence message = sequence(messageId, application(0, protocolVersion, username, choice(0, password)));
	}
	
//	UnbindRequest ::= [APPLICATION 2] NULL
	public static final class UnbindRequest {
		public final AsnInteger messageId = integer();
		public final AsnString nullValue = nullValue();
		public final AsnSequence message = sequence(messageId, application(2, nullValue));
	}
}
