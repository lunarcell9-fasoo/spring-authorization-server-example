package com.lunarcell.authorizationServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

	@Bean
	@Order(3)
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/messages/**")
                .authorizeHttpRequests((authorize) -> authorize
                	.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
				)
			.oauth2ResourceServer(resourceServer -> resourceServer
				.jwt(jwt -> jwt
					.jwtAuthenticationConverter(jwtAuthenticationConverter())
				)
			);
		
		return http.build();
	}

	private JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter jwtScopeConverter = new JwtGrantedAuthoritiesConverter();

        JwtGrantedAuthoritiesConverter jwtRoleConverter = new JwtGrantedAuthoritiesConverter();
        jwtRoleConverter.setAuthoritiesClaimName("roles");
        jwtRoleConverter.setAuthorityPrefix("ROLE_");

		DelegatingJwtGrantedAuthoritiesConverter delegatingConverter = 
			new DelegatingJwtGrantedAuthoritiesConverter(jwtScopeConverter, jwtRoleConverter);
		
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(delegatingConverter);

        return jwtAuthenticationConverter;
	}
}
