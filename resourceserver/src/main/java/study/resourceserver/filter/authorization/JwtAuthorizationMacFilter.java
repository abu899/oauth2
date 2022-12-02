package study.resourceserver.filter.authorization;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

@RequiredArgsConstructor
public class JwtAuthorizationMacFilter extends OncePerRequestFilter {

    private final OctetSequenceKey octetSequenceKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.replace("Bearer ", "");

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
            MACVerifier macVerifier = new MACVerifier(octetSequenceKey.toSecretKey());
            if (signedJWT.verify(macVerifier)) {
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                String username = (String) claims.getClaim("username");
                List<String> authorities = (List<String>) claims.getClaim("authority");

                if (StringUtils.hasText(username)) {
                    UserDetails user = User.withUsername(username)
                            .password(UUID.randomUUID().toString())
                            .authorities(authorities.get(0))
                            .build();

                    UsernamePasswordAuthenticationToken authentication
                            = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
        }
        filterChain.doFilter(request, response);
    }
}
