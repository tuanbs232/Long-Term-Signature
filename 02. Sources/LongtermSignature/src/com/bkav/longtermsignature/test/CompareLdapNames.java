package com.bkav.longtermsignature.test;

import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/*
 * Shows ways of comparing LDAP names
 */
public class CompareLdapNames {
	public static void main(String args[]) {
		try {
			LdapName one = new LdapName(
					"cn=Vincent Ryan, ou=People, o=JNDITutorial");
			LdapName two = new LdapName(
					"cn=Vincent Ryan, o=JNDITutorial, ou=People");

			List<Rdn> rdns = one.getRdns();
			List<Rdn> twoRdns = two.getRdns();
			boolean equal = true;

			if (rdns.size() != twoRdns.size()) {
				equal = false;
			} else {
				for (Rdn rdn : twoRdns) {
					if (!rdns.contains(rdn)) {
						equal = false;
						break;
					}

				}
			}
			System.out.println(equal);

			// System.out.println(one.startsWith(three)); // true
			// System.out.println(one.endsWith(two)); // true
			// System.out.println(one.startsWith(four)); // true
			// System.out.println(one.endsWith(four)); // true
			// System.out.println(one.endsWith(three)); // false
			// System.out.println(one.isEmpty()); // false
			// System.out.println(four.isEmpty()); // true
			// System.out.println(four.size() == 0); // true
		} catch (InvalidNameException e) {
			e.printStackTrace();
		}
	}
}