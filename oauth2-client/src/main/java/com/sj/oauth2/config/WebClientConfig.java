package com.sj.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;

public class WebClientConfig {

//    @Bean
//    WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
//        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
//                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
//        return WebClient.builder()
//                .apply(oauth2Client.oauth2Configuration())
//                .build();
//    }

    /**
     * 负责与一个或者多个OAuth2AuthorizedClientProvider 管理客户端授权
     * 提供authorization_code、refresh_token的支持
     * @param clientRegistrationRepository
     * @param authorizedClientRepository
     * @return
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .build();
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        return authorizedClientManager;
    }

}
