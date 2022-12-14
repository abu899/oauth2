package study.resourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.resourceserver.filter.authentication.JwtAuthenticationFilter;
import study.resourceserver.filter.authorization.JwtAuthorizationMacFilter;
import study.resourceserver.filter.authorization.JwtAuthorizationRsaFilter;
import study.resourceserver.signature.MacSecuritySigner;
import study.resourceserver.signature.RsaSecuritySigner;

//@Configuration
@RequiredArgsConstructor
//@EnableWebSecurity
public class OAuth2ResourceServerConfig {

    private final OAuth2ResourceServerProperties properties;
    private final AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // JWT ?????????
//        http.authorizeRequests(request -> request.anyRequest().authenticated());
//        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        http.csrf().disable();
        http.authorizeRequests((requests) -> requests.antMatchers("/").permitAll()
                .anyRequest().authenticated());
        http.userDetailsService(userDetailsService());


        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);

        /**
         * MAC ??????
         */
//        Filter ?????? ??????
//        http.addFilterBefore(jwtAuthorizationMacFilter(null), UsernamePasswordAuthenticationFilter.class);

        /**
         * RSA ??????
         */
//        Filter ?????? ??????
//        http.addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class);

        /**
         * JWTDecoder ?????? ??????(MAC & RSA ??????)
         */
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }

//    @Bean
//    public JwtAuthenticationFilter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) throws Exception {
//        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(macSecuritySigner, octetSequenceKey);
//        jwtAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
//        return jwtAuthenticationFilter;
//    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
        return jwtAuthenticationFilter;
    }

    @Bean
    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
    }

    @Bean
    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
    }

    // ?????????????????? ???????????? JwtDecoder??? ????????? ??????
//    @Bean
    public JwtDecoder jwtDecoder1() {
        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    }

    //    @Bean
    public JwtDecoder jwtDecoder2() {
        return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
    }

    // ?????? jwkSetUri??? ?????? ???????????? ??????
    @Bean
    public JwtDecoder jwtDecoder3() {
        return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS512)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("1234")
                .authorities("ROLE_USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
