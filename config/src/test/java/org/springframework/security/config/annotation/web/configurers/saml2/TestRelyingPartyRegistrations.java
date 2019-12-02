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

package org.springframework.security.config.annotation.web.configurers.saml2;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;

import static org.springframework.security.config.annotation.web.configurers.saml2.TestSaml2Credentials.signingCredential;
import static org.springframework.security.config.annotation.web.configurers.saml2.TestSaml2Credentials.verificationCertificate;

/**
 * Preconfigured test data for {@link RelyingPartyRegistration} objects
 */
public class TestRelyingPartyRegistrations {

	static RelyingPartyRegistration saml2AuthenticationConfiguration() {
		//remote IDP entity ID
		String idpEntityId = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		//remote WebSSO Endpoint - Where to Send AuthNRequests to
		String webSsoEndpoint = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php";
		//local registration ID
		String registrationId = "simplesamlphp";
		//local entity ID - autogenerated based on URL
		String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
		//local signing (and decryption key)
		Saml2X509Credential signingCredential = signingCredential();
		//IDP certificate for verification of incoming messages
		Saml2X509Credential idpVerificationCertificate = verificationCertificate();
		String acsUrlTemplate = "{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;
		return RelyingPartyRegistration.withRegistrationId(registrationId)
				.remoteIdpEntityId(idpEntityId)
				.idpWebSsoUrl(webSsoEndpoint)
				.credentials(c -> c.add(signingCredential))
				.credentials(c -> c.add(idpVerificationCertificate))
				.localEntityIdTemplate(localEntityIdTemplate)
				.assertionConsumerServiceUrlTemplate(acsUrlTemplate)
				.build();
	}


}
