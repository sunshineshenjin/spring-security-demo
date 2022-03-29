package com.sj.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SecurityConfig {
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
                .oauth2Client(withDefaults());
        return http.build();
    }
}
