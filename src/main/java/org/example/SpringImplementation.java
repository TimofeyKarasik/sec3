package org.example;

import static org.example.ManualImplementation.VK_OAUTH_CLIENT_ID;
import static org.example.ManualImplementation.VK_OAUTH_CLIENT_SECRET;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

public class SpringImplementation {
    @Bean
    SecurityFilterChain filterChainBuiltin(HttpSecurity http) throws Exception{
        return http
                .authorizeHttpRequests(c -> c.requestMatchers("*/**").authenticated())
                .oauth2Login(c -> {
                    c.clientRegistrationRepository(
                            new InMemoryClientRegistrationRepository(
                                    ClientRegistration.withRegistrationId("vk")
                                            .clientId(VK_OAUTH_CLIENT_ID)
                                            .clientSecret(VK_OAUTH_CLIENT_SECRET)
                                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                                            .scope("email")
                                            .authorizationUri("https://oauth.vk.com/autherize")
                                            .tokenUri("https://oauth.vk.com/access_token")
                                            .userNameAttributeName("email")
                                            .clientName("Vk")
                                            .build()
                            )
                    );
                    c.tokenEndpoint(cc ->
                            cc.accessTokenResponseClient(codeGrantRequestData -> {
                                var client = codeGrantRequestData.getClientRegistration();
                                var token = RestClient.create().get()
                                        .uri("""
                                            https://oauth.vk.com/access_token\
                                            ?client_id=%s&client_secret=%s\
                                            &redirect_url=%s&code=%s\
                                            """
                                                .formatted(
                                                        client.getClientId(),client.getClientSecret(),
                                                        codeGrantRequestData.getAuthorizationExchange()
                                                                .getAuthorizationRequest().getRedirectUri(),
                                                        codeGrantRequestData.getAuthorizationExchange()
                                                                .getAuthorizationResponse().getCode()
                                                )
                                        )
                                        .retrieve().body(ManualImplementation.VkTokenResponse.class);

                                return  OAuth2AccessTokenResponse
                                        .withToken(token.accesToken)
                                        .tokenType(OAuth2AccessToken.TokenType.BEARER)
                                        .additionalParameters(
                                                Map.of("vkId",token.userId, "email", token.email)
                                        )
                                        .build();

                            })
                    );
                    c.userInfoEndpoint(cc->
                            cc.userService(userRequestDate ->
                                    new DefaultOAuth2User(
                                            List.of(new SimpleGrantedAuthority("ROLE_USER")),
                                            userRequestDate.getAdditionalParameters(),"email"
                                    )
                            )
                    );
                }).build();

    }

}