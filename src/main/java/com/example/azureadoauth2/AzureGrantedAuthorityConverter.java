package com.example.azureadoauth2;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

public class AzureGrantedAuthorityConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {

        return Optional.ofNullable(source.getClaimAsStringList("roles"))
                .orElse(Collections.emptyList())
                .stream()
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toCollection(ArrayList::new));
    }
}
