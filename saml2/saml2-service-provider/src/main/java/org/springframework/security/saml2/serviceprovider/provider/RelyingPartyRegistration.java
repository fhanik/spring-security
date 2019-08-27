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

package org.springframework.security.saml2.serviceprovider.provider;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage;
import org.springframework.util.Assert;

import static java.util.Arrays.asList;
import static org.springframework.util.Assert.hasText;
import static org.springframework.util.Assert.notEmpty;
import static org.springframework.util.Assert.notNull;

/**
 * Represents a configured service provider, SP, and a remote identity provider, IDP, pair.
 * Each SP/IDP pair is uniquely identified using a <code>registrationId</code>, an arbitrary string.
 * A fully configured registration may look like
 * <pre>
 *		//remote IDP entity ID
 *		String idpEntityId = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
 *		//remote WebSSO Endpoint - Where to Send AuthNRequests to
 *		String webSsoEndpoint = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php";
 *		//local registration ID
 *		String registrationId = "simplesamlphp";
 *		//local entity ID - autogenerated based on URL
 *		String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
 *		//local signing (and local decryption key and remote encryption certificate)
 *		Saml2X509Credential signingCredential = getSigningCredential();
 *		//IDP certificate for verification of incoming messages
 *		Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();
 *		RelyingPartyRegistration rp = RelyingPartyRegistration.withRegistrationId(registrationId)
 * 				.remoteIdpEntityId(idpEntityId)
 * 				.idpWebSsoUrl(webSsoEndpoint)
 * 				.credential(signingCredential)
 * 				.credential(idpVerificationCertificate)
 * 				.localEntityIdTemplate(localEntityIdTemplate)
 * 				.build();
 * </pre>
 * @since 5.2
 */
public class RelyingPartyRegistration {

	private final String registrationId;
	private final String remoteIdpEntityId;
	private final String idpWebSsoUrl;
	private final List<Saml2X509Credential> credentials;
	private final String localEntityIdTemplate;

	private RelyingPartyRegistration(String idpEntityId, String registrationId, String idpWebSsoUri, List<Saml2X509Credential> credentials, String localEntityIdTemplate) {
		hasText(idpEntityId, "idpEntityId cannot be empty");
		hasText(registrationId, "registrationId cannot be empty");
		hasText(localEntityIdTemplate, "localEntityIdTemplate cannot be empty");
		notEmpty(credentials, "credentials cannot be empty");
		notNull(idpWebSsoUri, "idpWebSsoUri cannot be empty");
		for (Saml2X509Credential c : credentials) {
			notNull(c, "credentials cannot contain null elements");
		}
		this.remoteIdpEntityId = idpEntityId;
		this.registrationId = registrationId;
		this.credentials = new LinkedList<>(credentials);
		this.idpWebSsoUrl = idpWebSsoUri;
		this.localEntityIdTemplate = localEntityIdTemplate;
	}

	public String getRemoteIdpEntityId() {
		return this.remoteIdpEntityId;
	}

	public String getRegistrationId() {
		return this.registrationId;
	}

	public String getIdpWebSsoUrl() {
		return this.idpWebSsoUrl;
	}

	public String getLocalEntityIdTemplate() {
		return this.localEntityIdTemplate;
	}

	public List<Saml2X509Credential> getCredentialsForUsage(Saml2X509CredentialUsage... types) {
		if (types == null || types.length == 0) {
			return this.credentials;
		}
		Set<Saml2X509CredentialUsage> typeset = new HashSet<>(asList(types));
		List<Saml2X509Credential> result = new LinkedList<>();
		for (Saml2X509Credential c : this.credentials) {
			if (containsCredentialForTypes(c.getSaml2X509CredentialUsages(), typeset)) {
				result.add(c);
			}
		}
		return result;
	}

	private boolean containsCredentialForTypes(Set<Saml2X509CredentialUsage> existing, Set<Saml2X509CredentialUsage> requested) {
		for (Saml2X509CredentialUsage u : requested) {
			if (existing.contains(u)) {
				return true;
			}
		}
		return false;
	}

	public static Builder withRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return new Builder(registrationId);
	}

	public static class Builder {
		private String registrationId;
		private String remoteIdpEntityId;
		private String idpWebSsoUrl;
		private List<Saml2X509Credential> credentials = new LinkedList<>();
		private String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";

		private Builder(String registrationId) {
			this.registrationId = registrationId;
		}

		public Builder registrationId(String id) {
			this.registrationId = registrationId;
			return this;
		}

		public Builder remoteIdpEntityId(String entityId) {
			this.remoteIdpEntityId = entityId;
			return this;
		}

		public Builder idpWebSsoUrl(String url) {
			this.idpWebSsoUrl = url;
			return this;
		}

		public Builder credential(Saml2X509Credential credential) {
			this.credentials.add(credential);
			return this;
		}

		public Builder credentials(Collection<Saml2X509Credential> credentials) {
			this.credentials.addAll(credentials);
			return this;
		}

		public Builder localEntityIdTemplate(String template) {
			this.localEntityIdTemplate = template;
			return this;
		}

		public RelyingPartyRegistration build() {
			return new RelyingPartyRegistration(
					remoteIdpEntityId,
					registrationId,
					idpWebSsoUrl,
					credentials,
					localEntityIdTemplate
			);
		}
	}


}
