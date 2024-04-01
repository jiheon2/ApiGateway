package jiheon.poly.config;

import jiheon.poly.filter.JwtAuthenticationFilter;
import jiheon.poly.handler.AccessDeniedHandler;
import jiheon.poly.handler.LoginServerAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class SecurityConfig {

    private final AccessDeniedHandler accessDeniedHandler; // 인증 에러 처리

    private final LoginServerAuthenticationEntryPoint loginServerAuthenticationEntryPoint; // 인가 에러 처리

    // JWT 검증을 위한 필터
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {

        log.info(this.getClass().getName() + ".filterChain Start!");

        http.csrf(ServerHttpSecurity.CsrfSpec::disable); // post방식 전송을 위해 csrf 막기
        http.cors(ServerHttpSecurity.CorsSpec::disable); // CORS 사용하지 않음
        http.formLogin(ServerHttpSecurity.FormLoginSpec::disable); // 로그인 기능 사용x

        http.exceptionHandling(exceptionHandlingSpec ->
                exceptionHandlingSpec.accessDeniedHandler(accessDeniedHandler)); // 인증 에러 처리

        http.exceptionHandling(exceptionHandlingSpec ->
                exceptionHandlingSpec.authenticationEntryPoint(loginServerAuthenticationEntryPoint)); // 인가 에러 처리

        // stateless 방식의 애플리케이션이 되도록 설정
        http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

        http.authorizeExchange(authz -> authz
                .pathMatchers("/notice/**").hasAnyAuthority("ROLE_USER")
        );

        // Spring Security 필터들이 실행되기 전에 JWT 필터 실행
        http.addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);

        log.info(this.getClass().getName() + ".filterChain End!");

        return http.build();
    }
}
