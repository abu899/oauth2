package study.resourceserver.filter.authorization;

import com.nimbusds.jose.JWSVerifier;

public class JwtAuthorizationMacFilter extends JwtAuthorizationFilter {

    public JwtAuthorizationMacFilter(JWSVerifier jwsVerifier) {
        super(jwsVerifier);
    }
}