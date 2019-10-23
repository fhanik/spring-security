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

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.lang.String.format;

/**
 * @since 5.2
 */
public class Saml2MetadataFilter extends OncePerRequestFilter {

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private RequestMatcher redirectMatcher = new AntPathRequestMatcher("/saml2/service-provider-metadata/{registrationId}");

	public Saml2MetadataFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
	}

	public void setRedirectMatcher(RequestMatcher redirectMatcher) {
		Assert.notNull(redirectMatcher, "redirectMatcher cannot be null");
		this.redirectMatcher = redirectMatcher;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		MatchResult matcher = this.redirectMatcher.matcher(request);
		if (!matcher.isMatch()) {
			filterChain.doFilter(request, response);
			return;
		}

		String registrationId = matcher.getVariables().get("registrationId");
		writeSaml2Metadata(request, response, registrationId);
	}

	private void writeSaml2Metadata(HttpServletRequest request, HttpServletResponse response, String registrationId)
			throws IOException {
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(format("Creating SAML2 SP Metadata Request for IDP[%s]", registrationId));
		}
		RelyingPartyRegistration relyingParty = this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
	}


}
