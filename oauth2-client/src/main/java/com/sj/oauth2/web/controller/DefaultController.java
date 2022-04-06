/*
 * Copyright 2020 the original author or authors.
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
package com.sj.oauth2.web.controller;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

/**
 * @since 0.0.1
 */
@RestController
@Slf4j
public class DefaultController {

	private SecurityContextRepository securityContextRepository;

	@Autowired
	private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

	@GetMapping("/")
	public String root(HttpServletRequest request, HttpServletResponse response) {
		return "sdksdsdka";
	}

	@GetMapping("/index")
	public String index(HttpServletRequest request, HttpServletResponse response) {
		SecurityContext context = SecurityContextHolder.getContext();
		JSONObject jsonObject = new JSONObject();
		if (!Objects.isNull(context)) {
			log.info("获取到context");
			OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) context.getAuthentication();
			DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
			OAuth2AuthorizedClient oAuth2AuthorizedClient  = oAuth2AuthorizedClientService.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication.getName());
			if (!Objects.isNull(oAuth2AuthorizedClient)) {
				jsonObject.put("accessToken", oAuth2AuthorizedClient.getAccessToken());
				jsonObject.put("refreshToken", oAuth2AuthorizedClient.getRefreshToken());
			}
			jsonObject.put("oidcUser", oidcUser);
			return jsonObject.toJSONString();
		}
		return jsonObject.toJSONString();
	}
}
