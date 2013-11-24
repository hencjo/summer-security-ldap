package com.hencjo.summer.security.ldap;

import static com.hencjo.summer.security.ldap.asn.ASN.*;

public class LdapMessages {
/*
 * BindResponse ::= [APPLICATION 1] SEQUENCE {
 *           COMPONENTS OF LDAPResult}
 * 
 * LDAPResult ::= SEQUENCE {
 *           resultCode         ENUMERATED {
 *                success                      (0),
 *                ...},
 *           matchedDN          LDAPDN,
 *           diagnosticMessage  LDAPString,
 *           ... }   
 */
	public static final class BindResponse {
		public final AsnInteger messageId = integer();
		public final AsnEnumerated resultCode = enumerated();
		public final AsnString matchedDn = string();
		public final AsnString diagnosticMessage = string();
		public final AsnSequence message = sequence(messageId, application(1, resultCode, matchedDn, diagnosticMessage));
	}

/*
 *   BindRequest ::= [APPLICATION 0] SEQUENCE {
 *           version                 INTEGER (1 ..  127),
 *           name                    LDAPDN,
 *           authentication          AuthenticationChoice }
 *
 *      AuthenticationChoice ::= CHOICE {
 *           simple                  [0] OCTET STRING,
 *           ...  }
 */
	public static final class BindRequest {
		public final AsnInteger messageId = integer();
		public final AsnInteger protocolVersion = integer();
		public final AsnString username = string();
		public final AsnRaw password = raw();
		public final AsnSequence message = sequence(messageId, application(0, protocolVersion, username, choice(0, password)));
	}
	
/*
 * 	UnbindRequest ::= [APPLICATION 2] NULL
 */
	public static final class UnbindRequest {
		public final AsnInteger messageId = integer();
		public final AsnString nullValue = nullValue();
		public final AsnSequence message = sequence(messageId, application(2, nullValue));
	}
}
