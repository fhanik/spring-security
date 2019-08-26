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
package org.springframework.security.samples;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("multipleidps")
public class ServiceProviderMultipleIdpsTests {

	@Autowired
	MockMvc mockMvc;

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	public void redirectToLoginPage() throws Exception {
		mockMvc.perform(get("http://localhost:8080/some/url"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost:8080/login"));
	}

	@Test
	public void loginPage() throws Exception {
		mockMvc.perform(get("http://localhost:8080/login"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString(">simplesamlphp<")))
			.andExpect(content().string(containsString(">simplesamlphp2<")))
		;
	}

}
