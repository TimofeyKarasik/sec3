package org.example;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.client.RestClient;

import java.security.Principal;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;

public class ManualImplementation {
    static final String OAUTH_REDIRECT_PATH = "/oauth/authorize";
    static final String OAUTH_REDIRECT_URL = "http://localhost:8080" + OAUTH_REDIRECT_PATH;
    static final String VK_OAUTH_CLIENT_ID = "51466128";
    static final String VK_OAUTH_CLIENT_SECRET = "f4E9B4OHxfypUK0N7VZL";
    static final String OAUTH_SESSION_STATE_ATTRIB = "OAUTH2_STATE";

    @JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
    public static class VkTokenResponse {
        public Long userId;
        public String email;
        public String accesToken;
        public Long expiresId;
    }

    static class VkAuthenticationToken implements Authentication {
        private boolean isAuthenticated = true;
        private final String email;
        private final Long vkId;

        @Override
        public String toString() {
            return "VkAuthenticationToken{" +
                    "email='" + email + '\'' +
                    ", vkId=" + vkId +
                    '}';
        }

        record Details(String email, Long vkID) {
        }

        VkAuthenticationToken(String email, Long vkId) {
            this.email = email;
            this.vkId = vkId;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return new Details(email, vkId);
        }

        @Override
        public Object getPrincipal(){return (Principal)() -> email;}

        @Override
        public boolean isAuthenticated(){return isAuthenticated;}

        @Override
        public void setAuthenticated(boolean isAuthenticated)
                throws IllegalArgumentException{
            this.isAuthenticated = isAuthenticated;
        }

        @Override
        public String getName(){return null;}
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http)
            throws Exception{
        //   var authenticationManager = http.getSharedObjects(AuthenticationManager.class);
        //  var authenticationManager2 = http.getSharedObjects(AuthenticationManager.class);
        var random = new SecureRandom();
        var contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        var securityContextRepository = new HttpSessionSecurityContextRepository();
        var fc = http
                .authorizeHttpRequests(c-> c.requestMatchers("/**").authenticated()
                )
                .exceptionHandling(c->
                        c.authenticationEntryPoint(
                                (request,responce,authException) ->
                                {
                                    var state = random.nextLong();
                                    request.getSession().setAttribute(OAUTH_SESSION_STATE_ATTRIB,state);
                                    responce.sendRedirect("""
                                            https://oauth.vk.com/authorize\
                                            ?client_id=%s&redirect_url=%s\
                                            &scope=email&response_type=code\
                                            &state=%d&v=5.131\
                                            """.formatted(VK_OAUTH_CLIENT_ID,OAUTH_REDIRECT_URL,state)
                                    );
                                }
                        )
                )
                .addFilterAfter((request,responce,filterChain) ->{
                    if (
                            ((HttpServletRequest) request).getServletPath()
                                    .equals(OAUTH_REDIRECT_PATH)
                    ) {
                        var code = request.getParameter("code");
                        var state = Long.parseLong(request.getParameter("state"));
                        var originalState = (Long)((HttpServletRequest) request).getSession()
                                .getAttribute(OAUTH_SESSION_STATE_ATTRIB);
                        ((HttpServletRequest) request).getSession()
                                .setAttribute(OAUTH_SESSION_STATE_ATTRIB,null);
                        if (state == originalState) throw new RuntimeException("state Exception");

                        var token = RestClient.create().get()
                                .uri("""
                                        https://oauth.vk.com/access_token\
                                            ?client_id=%s&client_secret=%s\
                                            &redirect_url=%s&code=%s\
                                            """
                                        .formatted(
                                                VK_OAUTH_CLIENT_ID,VK_OAUTH_CLIENT_SECRET,OAUTH_REDIRECT_URL,code
                                        )
                                )
                                .retrieve().body(VkTokenResponse.class);


                        var context = contextHolderStrategy.createEmptyContext();
                        var authentication = new VkAuthenticationToken(token.email,token.userId);
                        context.setAuthentication(authentication);

                        contextHolderStrategy.setContext(context);
                        securityContextRepository.saveContext(
                                context,(HttpServletRequest) request, (HttpServletResponse) responce
                        );

                        var next = new SavedRequestAwareAuthenticationSuccessHandler();
                        next.onAuthenticationSuccess(
                                (HttpServletRequest) request, (HttpServletResponse) responce, authentication
                        );

                        return;
                    }

                    filterChain.doFilter(request,responce);
                }, LogoutFilter.class)
                .build();
        return fc;
    }

}
