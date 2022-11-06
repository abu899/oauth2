package io.security.cors2;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests().anyRequest().authenticated();
        http.cors().configurationSource(corsConfigurationSource());
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration conf = new CorsConfiguration();
        conf.addAllowedOrigin("*");
        conf.addAllowedMethod("*");
        conf.addAllowedHeader("*");
//        conf.setAllowCredentials(true);
        conf.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource urlConf = new UrlBasedCorsConfigurationSource();
        urlConf.registerCorsConfiguration("/**", conf);

        return urlConf;
    }


}
