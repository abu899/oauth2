package study.resourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

@Configuration
@RequiredArgsConstructor
public class JwtDecoderConfig {

    private final OAuth2ResourceServerProperties properties;

    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt",
            name = "jws-algorithms", havingValue = "HS256")
    public JwtDecoder jwtDecoderBySecretKeyValue(OctetSequenceKey octetSequenceKey, OAuth2ResourceServerProperties properties) {
        return NimbusJwtDecoder.withSecretKey(octetSequenceKey.toSecretKey())
                .macAlgorithm(MacAlgorithm.from(properties.getJwt().getJwsAlgorithms().get(0)))
                .build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt",
            name = "jws-algorithms", havingValue = "RS256")
    public JwtDecoder jwtDecoderByPublicKey(RSAKey rsaKey, OAuth2ResourceServerProperties properties) throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.from(properties.getJwt().getJwsAlgorithms().get(0)))
                .build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt",
            name = "jwk-set-uri")
    public JwtDecoder jwtDecoderByJwkKeySetUri() throws JOSEException {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
                .jwsAlgorithms(this::jwsAlgorithms)
                .build();

        String issuerUri = properties.getJwt().getIssuerUri();
        Supplier<OAuth2TokenValidator<Jwt>> defaultValidator =
                (null != issuerUri) ? () -> JwtValidators.createDefaultWithIssuer(issuerUri) : JwtValidators::createDefault;
        jwtDecoder.setJwtValidator(getValidators(defaultValidator));

        return jwtDecoder;
    }

    private void jwsAlgorithms(Set<SignatureAlgorithm> algorithms) {
        for (String algorithm : properties.getJwt().getJwsAlgorithms()) {
            algorithms.add(SignatureAlgorithm.from(algorithm));
        }
    }

    private OAuth2TokenValidator<Jwt> getValidators(Supplier<OAuth2TokenValidator<Jwt>> defaultValidator) {
        OAuth2TokenValidator<Jwt> defaultValidators = defaultValidator.get();
        List<String> audiences = properties.getJwt().getAudiences();
        if (audiences.isEmpty()) {
            return defaultValidators;
        }

        List<OAuth2TokenValidator<Jwt>> returnValidators = new ArrayList<>();
        returnValidators.add(defaultValidators);
        returnValidators.add(new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                (aud) -> null != aud && !Collections.disjoint(aud, audiences)));

        return new DelegatingOAuth2TokenValidator<Jwt>(returnValidators);
    }
}
