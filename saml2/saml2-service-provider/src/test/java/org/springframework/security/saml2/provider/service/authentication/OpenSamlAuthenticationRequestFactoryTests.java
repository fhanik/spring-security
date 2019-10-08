package org.springframework.security.saml2.provider.service.authentication;

import org.springframework.security.saml2.Saml2Exception;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyCredentials;

public class OpenSamlAuthenticationRequestFactoryTests {

	private OpenSamlAuthenticationRequestFactory factory;
	private Saml2AuthenticationRequest request;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() {
		request = Saml2AuthenticationRequest.builder()
				.issuer("https://issuer")
				.destination("https://destination/sso")
				.assertionConsumerServiceUrl("https://issuer/sso")
				.credentials(c -> c.addAll(relyingPartyCredentials()))
				.build();
		factory = new OpenSamlAuthenticationRequestFactory();
	}

	@Test
	public void createAuthenticationRequestWhenDefaultThenReturnsPostBinding() {
		AuthnRequest authn = getAuthNRequest();
		Assert.assertEquals(SAMLConstants.SAML2_POST_BINDING_URI, authn.getProtocolBinding());
	}

	@Test
	public void createAuthenticationRequestWhenSetUriThenReturnsCorrectBinding() {
		factory.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		AuthnRequest authn = getAuthNRequest();
		Assert.assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authn.getProtocolBinding());
	}

	@Test
	public void createAuthenticationRequestWhenSetUnsupportredUriThenThrowsSaml2Exception() {
		factory.setProtocolBinding("my-invalid-binding");
		exception.expect(Saml2Exception.class);
		exception.expectMessage(containsString("my-invalid-binding"));
	}

	private AuthnRequest getAuthNRequest() {
		String xml = factory.createAuthenticationRequest(request);
		return (AuthnRequest) OpenSamlImplementation.getInstance().resolve(xml);
	}
}
