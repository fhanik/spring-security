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

package org.springframework.security.saml2.provider.service.registration;

/**
 * The type of bindings that messages are exchanged using
 * Supported bindings are {@code urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST}
 * and {@code urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect}.
 * In addition there is support for {@code urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect}
 * with an XML signature in the message rather than query parameters.
 * @since 5.3
 */
public enum Saml2MessageBinding {

	POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
	REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
	REDIRECT_XML_SIGNATURE("urn:oasis:names:tc:SAML:2.0:bindings:URI"),
	POST_SIMPLE("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign")
	;

	private final String urn;

	Saml2MessageBinding(String s) {
		this.urn = s;
	}

	public String getUrn() {
		return urn;
	}
}
