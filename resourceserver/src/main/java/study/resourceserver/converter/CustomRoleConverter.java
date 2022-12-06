package study.resourceserver.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String PREFIX = "ROLE_";
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {

        String scope = source.getClaimAsString("scope");
        Map<String, Object> realm_access = source.getClaimAsMap("realm_access");

        if (!StringUtils.hasText(scope) || realm_access.isEmpty()) {
            return Collections.EMPTY_LIST;
        }

        List<GrantedAuthority> authorities1 = Arrays.stream(scope.split(" "))
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        List<GrantedAuthority> authorities2 = ((List<String>)realm_access.get("roles")).stream()
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorities1.addAll(authorities2);
        return authorities1;
    }
}
