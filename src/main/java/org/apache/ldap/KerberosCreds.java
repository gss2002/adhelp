package org.apache.ldap;

import javax.security.auth.Subject;

public final class KerberosCreds {
	public static Subject subject;


	public static Subject getSubject() {
		return subject;
	}

	public static void setSubject(Subject subject) {
		KerberosCreds.subject = subject;
	}
}
