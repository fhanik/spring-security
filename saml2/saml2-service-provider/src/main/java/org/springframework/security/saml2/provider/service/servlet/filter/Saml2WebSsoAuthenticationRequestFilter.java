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

import org.springframework.http.MediaType;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.POST;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.REDIRECT_XML_SIGNATURE;
import static org.springframework.security.saml2.provider.service.servlet.filter.Saml2Utils.deflate;
import static org.springframework.security.saml2.provider.service.servlet.filter.Saml2Utils.encode;
import static org.springframework.web.util.HtmlUtils.htmlEscape;

/**
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationRequestFilter extends OncePerRequestFilter {

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private RequestMatcher redirectMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}");

	private Saml2AuthenticationRequestFactory authenticationRequestFactory = new OpenSamlAuthenticationRequestFactory();

	public Saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
	}

	public void setAuthenticationRequestFactory(Saml2AuthenticationRequestFactory authenticationRequestFactory) {
		Assert.notNull(authenticationRequestFactory, "authenticationRequestFactory cannot be null");
		this.authenticationRequestFactory = authenticationRequestFactory;
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
		sendResponseData(request, response, registrationId);
	}

	private void sendResponseData(HttpServletRequest request, HttpServletResponse response, String registrationId)
			throws IOException {
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(format("Creating SAML2 SP Authentication Request for IDP[%s]", registrationId));
		}
		RelyingPartyRegistration relyingParty = this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
		if (POST == relyingParty.getIdpSsoConfiguration().getBinding()) {
			String formData = createSamlRequestFormData(request, relyingParty);
			response.setContentType(MediaType.TEXT_HTML_VALUE);
			response.setCharacterEncoding(UTF_8.name());
			response.getWriter().write(formData);
		}
		else {
			String redirectUrl = createSamlRequestRedirectUrl(request, relyingParty);
			response.sendRedirect(redirectUrl);
		}
	}

	private RequestData getRequestParameters(
			HttpServletRequest request,
			RelyingPartyRegistration relyingParty,
			boolean isRedirect) {
		boolean sign = relyingParty.getIdpSsoConfiguration().isSignAuthNRequest();
		boolean useXmlSig = useXmlSig(relyingParty);
		Saml2AuthenticationRequest authNRequest = createAuthenticationRequest(relyingParty, request, sign && useXmlSig);
		String xml = this.authenticationRequestFactory.createAuthenticationRequest(authNRequest);
		String encoded = encodeAndEscapeXml(xml, isRedirect);
		Map<String, String> queryParams = new LinkedHashMap<>();
		queryParams.put("SAMLRequest", encoded);
		String relayState = request.getParameter("RelayState");
		if (StringUtils.hasText(relayState)) {
			String relayStateEncoded = escapeValue(relayState, isRedirect);
			queryParams.put("RelayState", relayStateEncoded);
		}
		if (sign && !useXmlSig && isRedirect) {
			//SimpleSignature
			queryParams = this.authenticationRequestFactory.simpleSignSaml2Message(
					queryParams,
					relyingParty.getCredentials()
			);
		}
		return new RequestData(authNRequest, queryParams);
	}

	private String encodeAndEscapeXml(String xml, boolean isRedirect) {
		return isRedirect ?
				escapeValue(encode(deflate(xml)), isRedirect) :
				escapeValue(encode(xml.getBytes(StandardCharsets.UTF_8)), isRedirect);
	}

	private String escapeValue(String value, boolean isRedirect) {
		if (isRedirect) {
			return UriUtils.encode(value, ISO_8859_1);
		}
		else {
			return htmlEscape(value);
		}
	}

	private boolean useXmlSig(RelyingPartyRegistration relyingParty) {
		final Saml2MessageBinding binding = relyingParty.getIdpSsoConfiguration().getBinding();
		return binding == POST || binding == REDIRECT_XML_SIGNATURE;
	}

	private Saml2AuthenticationRequest createAuthenticationRequest(
			RelyingPartyRegistration relyingParty,
			HttpServletRequest request,
			boolean signMessage) {
		String localSpEntityId = Saml2Utils.getServiceProviderEntityId(relyingParty, request);
		List<Saml2X509Credential> credentials = signMessage ? relyingParty.getCredentials() : Collections.emptyList();
		return Saml2AuthenticationRequest
				.builder()
				.issuer(localSpEntityId)
				.destination(relyingParty.getIdpSsoConfiguration().getIdpWebSsoUrl())
				.credentials(c -> c.addAll(credentials))
				.assertionConsumerServiceUrl(
						Saml2Utils.resolveUrlTemplate(
								relyingParty.getAssertionConsumerServiceUrlTemplate(),
								Saml2Utils.getApplicationUri(request),
								relyingParty.getRemoteIdpEntityId(),
								relyingParty.getRegistrationId()
						)
				)
				.build();
	}

	private String createSamlRequestRedirectUrl(HttpServletRequest request, RelyingPartyRegistration relyingParty) {
		RequestData data = getRequestParameters(request, relyingParty, true);

		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(data.getRequest().getDestination());
		for (Map.Entry<String, String> entry : data.getRequestParameters().entrySet()) {
			uriBuilder.queryParam(entry.getKey(), entry.getValue());
		}
		return uriBuilder
				.build(true)
				.toUriString();
	}

	private String createSamlRequestFormData(HttpServletRequest request, RelyingPartyRegistration relyingParty) {
		RequestData data = getRequestParameters(request, relyingParty, false);

		StringBuilder postHtml = new StringBuilder()
				.append("<!DOCTYPE html>\n")
				.append("<html>\n")
				.append("    <head>\n")
				.append("        <meta charset=\"utf-8\" />\n")
				.append("    </head>\n")
				.append("    <body onload=\"document.forms[0].submit()\">\n")
				.append("        <noscript>\n")
				.append("            <p>\n")
				.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n")
				.append("                you must press the Continue button once to proceed.\n")
				.append("            </p>\n")
				.append("        </noscript>\n")
				.append("        \n")
				.append("        <form action=\"").append(data.getRequest().getDestination()).append("\" method=\"post\">\n")
				.append("            <div>\n")
				.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"")
				.append(data.getRequestParameters().get("SAMLRequest"))
				.append("\"/>\n")
				;
		if (data.getRequestParameters().containsKey("RelayState")) {
			postHtml
					.append("                <input type=\"hidden\" name=\"RelayState\" value=\"")
					.append(data.getRequestParameters().get("RelayState"))
					.append("\"/>\n");
		}
		postHtml
				.append("            </div>\n")
				.append("            <noscript>\n")
				.append("                <div>\n")
				.append("                    <input type=\"submit\" value=\"Continue\"/>\n")
				.append("                </div>\n")
				.append("            </noscript>\n")
				.append("        </form>\n")
				.append("        \n")
				.append("    </body>\n")
				.append("</html>")
				;
		return postHtml.toString();
	}

	private class RequestData {
		private final Saml2AuthenticationRequest request;
		private final Map<String, String> requestParameters;

		private RequestData(Saml2AuthenticationRequest request,
				Map<String, String> requestParameters) {
			this.request = request;
			this.requestParameters = requestParameters;
		}

		public Saml2AuthenticationRequest getRequest() {
			return request;
		}

		public Map<String, String> getRequestParameters() {
			return requestParameters;
		}
	}

}
