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
package sample;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @author Josh Cummings
 * @since 5.2.0
 */
@RunWith(SpringRunner.class)
@WebMvcTest(OAuth2ResourceServerController.class)
public class OAuth2ResourceServerControllerTests {

	@Autowired
	MockMvc mockMvc;

	@MockBean
	JwtDecoder jwtDecoder;

	@Test
	public void indexGreetsAuthenticatedUser() throws Exception {
		mockMvc.perform(get("/").with(jwt(jwt -> jwt.subject("ch4mpy"))))
				.andExpect(content().string(is("Hello, ch4mpy!")));
	}

	@Test
	public void messageCanBeReadWithScopeMessageReadAuthority() throws Exception {
		mockMvc.perform(get("/message").with(jwt(jwt -> jwt.claim("scope", "message:read"))))
				.andExpect(content().string(is("secret message")));

		mockMvc.perform(get("/message")
				.with(jwt().authorities(new SimpleGrantedAuthority(("SCOPE_message:read")))))
				.andExpect(content().string(is("secret message")));
	}

	@Test
	public void messageCanNotBeReadWithoutScopeMessageReadAuthority() throws Exception {
		mockMvc.perform(get("/message").with(jwt()))
				.andExpect(status().isForbidden());
	}

	@Test
	public void messageCanNotBeCreatedWithoutScopeMessageReadAuthority() throws Exception {
		mockMvc.perform(post("/message").content("Hello message").with(jwt()))
				.andExpect(status().isForbidden());
	}

	@Test
	public void messageCanBeCreatedWithoutScopeMessageWriteAuthorityShouldPassButFails()
			throws Exception {
		mockMvc.perform(post("/message").content("Hello message")
				.with(jwt(jwt -> jwt.claim("scope", "message:read"))))
				.andExpect(
						status().isOk()) // this test should pass but it fails because the request does not contain the csrf token
				.andExpect(content().string(is("Message was created. Content: Hello message")));
	}

	@Test
	public void messageCanBeCreatedWithoutScopeMessageReadAuthorityAndWithCsrfToken()
			throws Exception {
		mockMvc.perform(post("/message").content("Hello message")
				.with(jwt(jwt -> jwt.claim("scope", "message:read")))
				.with(csrf()))
				.andExpect(status().isOk())
				.andExpect(content().string(is("Message was created. Content: Hello message")));

		mockMvc.perform(post("/message").content("Hello message")
				.with(jwt().authorities(new SimpleGrantedAuthority(("SCOPE_message:read"))))
				.with(csrf()))
				.andExpect(status().isOk())
				.andExpect(content().string(is("Message was created. Content: Hello message")));
	}
}
