package com.sj.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private OAuth2AuthorizedClientService jdbcAuthorizedClientService;

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/webjars/**");
    }

    /**
     * .oauth2Login(oauth2Login ->
     * 				oauth2Login.loginPage("/oauth2/authorization/messaging-client-oidc")
     *  路径规则：/oauth2/auhorization/{registerId}
     * 	这里表明当前客户端使用oauth2 进行登陆，这个登陆的URL正好是
     * 	授权请求URL，会被 OAuth2AuthorizationRequestRedirectFilter 过滤器拦截，该过滤器发现
     * 	当前的URL是一个OAuth2AuthorizationRequest 请求，它就会重定向到授权服务器
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 这里需要指定需要 /oauth2/authorization/{clientId}的格式
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/oauth2/authorization/messaging-client-authorization-code"))
                .oauth2Client(httpSecurity -> {
                    httpSecurity.authorizedClientService(this.jdbcAuthorizedClientService);
                });
        return http.build();
    }

    /**
     * 使用数据库保存已经授权的请求，防止客户端重启后内存中的客户端授权信息丢失
     * 该jdbc 使用的表为oauth2_authorized_client, 该表为客户端专用
     * @param jdbcTemplate
     * @param clientRegistrationRepository
     * @return
     */
    @Bean
    OAuth2AuthorizedClientService jdbcAuthorizedClientService(JdbcTemplate jdbcTemplate, ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }
}
