/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;

import java.nio.charset.Charset;

/**
 * Data holder for {@code AuthNRequest} parameters to be sent using either the
 * {@link Saml2MessageBinding#POST} or {@link Saml2MessageBinding#REDIRECT} binding.
 * Data will be encoded and possibly deflated, but will not be escaped for transport,
 * ie URL encoded, {@link org.springframework.web.util.UriUtils#encode(String, Charset)}
 * or HTML encoded, {@link org.springframework.web.util.HtmlUtils#htmlEscape(String)}.
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf (line 2031)
 *
 * @see Saml2AuthenticationRequestFactory#createPostAuthenticationRequest(Saml2AuthenticationRequestContext)
 * @see Saml2AuthenticationRequestFactory#createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext)
 * @since 5.3
 */
abstract class AbstractSaml2AuthenticationRequest {

	private final String samlRequest;
	private final String relayState;
	private final String destination;
	private String issuer;

	/**
	 * Mandatory constructor for the {@link AbstractSaml2AuthenticationRequest}
	 * @param issuer - typically a URL, cannot be empty or null
	 * @param samlRequest - the SAMLRequest XML data, SAML encoded, cannot be empty or null
	 * @param relayState - RelayState value that accompanies the request, may be null
	 * @param destination - The destination, a URL, where to send the XML message, cannot be empty or null
	 */
	AbstractSaml2AuthenticationRequest(
			String issuer,
			String samlRequest,
			String relayState,
			String destination) {
		Assert.hasText(issuer, "issuer cannot be null or empty");
		Assert.hasText(samlRequest, "samlRequest cannot be null or empty");
		Assert.hasText(destination, "destination cannot be null or empty");
		this.issuer = issuer;
		this.destination = destination;
		this.samlRequest = samlRequest;
		this.relayState = relayState;
	}

	/**
	 * Returns the AuthNRequest Issuer value of this SP.
	 * @return the AuthNRequest Issuer value
	 */
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * Returns the AuthNRequest XML value to be sent. This value is already encoded for transport.
	 * If {@link #getBinding()} is {@link Saml2MessageBinding#REDIRECT} the value is deflated and SAML encoded.
	 * If {@link #getBinding()} is {@link Saml2MessageBinding#POST} the value is SAML encoded.
	 * @return the SAMLRequest parameter value
	 */
	public String getSamlRequest() {
		return this.samlRequest;
	}

	/**
	 * Returns the RelayState value, if present in the parameters
	 * @return the RelayState value, or null if not available
	 */
	public String getRelayState() {
		return this.relayState;
	}

	/**
	 * Returns the destination that this AuthNRequest should be sent to and
	 * the value stored inside the AuthNRequest XML
	 * @return the destination URL for this message
	 */
	public String getDestination() {
		return this.destination;
	}

	/**
	 * Returns the binding this AuthNRequest will be sent and
	 * encoded with. If {@link Saml2MessageBinding#REDIRECT} is used, the DEFLATE encoding will be automatically applied.
	 * @return the binding this message will be sent with.
	 */
	public abstract Saml2MessageBinding getBinding();

	/**
	 * A builder for {@link AbstractSaml2AuthenticationRequest} and its subclasses.
	 */
	static class Builder<T extends Builder<T>> {
		String destination;
		String samlRequest;
		String relayState;
		String issuer;

		protected Builder() {
		}

		/**
		 * Casting the return as the generic subtype, when returning itself
		 * @return this object
		 */
		@SuppressWarnings("unchecked")
		protected final T _this() {
			return (T) this;
		}


		/**
		 * Sets the {@code RelayState} parameter that will accompany this AuthNRequest
		 *
		 * @param relayState the relay state value, unencoded. if null or empty, the parameter will be removed from the
		 * map.
		 * @return this object
		 */
		public T relayState(String relayState) {
			this.relayState = relayState;
			return _this();
		}

		/**
		 * Sets the {@code issuer} value that was used to generate the request
		 *
		 * @param issuer the issuer state value, unencoded.
		 * @return this object
		 */
		public T issuer(String issuer) {
			this.issuer = issuer;
			return _this();
		}

		/**
		 * Sets the {@code SAMLRequest} parameter that will accompany this AuthNRequest
		 *
		 * @param samlRequest the SAMLRequest parameter.
		 * @return this object
		 */
		public T samlRequest(String samlRequest) {
			this.samlRequest = samlRequest;
			return _this();
		}

		/**
		 * Sets the {@code destination}, a URL that will receive the AuthNRequest message
		 *
		 * @param destination the relay state value, unencoded. if null or empty, the parameter will be removed from the
		 *                    map.
		 * @return this object
		 */
		public T destination(String destination) {
			this.destination = destination;
			return _this();
		}
	}

}
