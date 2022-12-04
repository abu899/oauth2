package study.resourceserver.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication, @AuthenticationPrincipal Jwt principal) {
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
        String sub = (String) authenticationToken.getTokenAttributes().get("sub");
        String email = (String) authenticationToken.getTokenAttributes().get("email");
        String scope = (String) authenticationToken.getTokenAttributes().get("scope");
        log.debug("JwtAuthenticationToken sub = {} , email = {}, scope = {}", sub, email, scope);

        String sub1 = principal.getClaim("sub");
        String email1 = principal.getClaim("email");
        String scope1 = principal.getClaim("scope");
        String token = principal.getTokenValue();
        log.debug("@AuthenticationPrincipal sub = {} , email = {}, scope = {}", sub1, email1, scope1);
        log.debug("token = {}", token);



        return authentication;
    }
}
