/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.provider.service.authentication;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;

import java.util.List;
import java.util.Map;

/**
 * Component that generates an AuthenticationRequest, <code>samlp:AuthnRequestType</code> as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 50, Line 2147
 *
 * @since 5.2
 */
public interface Saml2AuthenticationRequestFactory {
	/**
	 * Creates an authentication request from the Service Provider, sp,
	 * to the Identity Provider, idp.
	 * The authentication result is an XML string that may be signed, encrypted, both or neither.
	 *
	 * @param request - information about the identity provider, the recipient of this authentication request and
	 *                accompanying data
	 * @return XML data in the format of a String. This data may be signed, encrypted, both signed and encrypted or
	 * neither signed and encrypted
	 * @throws Saml2Exception when a SAML library exception occurs
	 */
	String createAuthenticationRequest(Saml2AuthenticationRequest request);

	default Map<String, String> simpleSignSaml2Message(
			Map<String, String> parameters,
			List<Saml2X509Credential> credentials
	) {
		throw new UnsupportedOperationException(
				Saml2AuthenticationRequestFactory.class.getName() + ".simpleSignSaml2Message is not implemented."
		);
	}
}
