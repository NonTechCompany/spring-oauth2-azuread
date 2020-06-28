package com.example.azureadoauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class Oauth2Configuration extends WebSecurityConfigurerAdapter {

  @Value("${spring.security.oauth2.resourceserver.audience}")
  private String audience;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests(a -> a.antMatchers("/azuread").fullyAuthenticated())
        .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter());
  }

  @Bean
  public JwtDecoder jwtDecoder(OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {
    NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(oAuth2ResourceServerProperties.getJwt().getJwkSetUri()).build();
    nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(Arrays.asList(
            new JwtIssuerValidator(oAuth2ResourceServerProperties.getJwt().getIssuerUri()),
            new JwtTimestampValidator(),
            new JwtClaimValidator<List<String>>("aud", audiences -> audiences.contains(audience))

    )));
    return nimbusJwtDecoder;
  }

  private Converter<Jwt, AbstractAuthenticationToken> authenticationConverter() {
    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new AzureGrantedAuthorityConverter());
    return jwtAuthenticationConverter;
  }
}
