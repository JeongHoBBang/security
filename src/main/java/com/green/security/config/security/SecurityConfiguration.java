package com.green.security.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


//spring security 5.7.0부터 WebSecurityConfigurerAdapter deprecated 됨
@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtTokenProvider jwtTokenProvider;

    //webSecurityCustomizer를 제외한 모든 것, 시큐리티를 거친다. 보안과 연관
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(authz ->
                    authz.requestMatchers( // 가변인자 String... 파라미터
                                     "/swagger.html"
                                    , "/swagger-ui/**"
                                    , "/v3/api-docs/**"
                                    , "/"
                                    , "/index.html" // 여기까지 default
                                    , "/static/**" // 리엑트 동작을 위한..

                                    ,"/sign-api/sign-in"
                                    , "/sign-api/sign-up"
                                    , "/sign-api/exception"

                                    , "/view/**"
                            ).permitAll() // 이 주소들은 모든 사람들이 사용 할 수 있도록 하겠다
                            .requestMatchers(HttpMethod.GET, "/sign-api/refresh-token").permitAll() // 이 주조소 들어오면 GET방식만 허용하겠다
                            .requestMatchers(HttpMethod.GET, "/product/**").permitAll() // /product 뒤에 뭐가 들어오든 허용
                            .requestMatchers("**exception**").permitAll() // 어디든 exception이 포함만 되어있으면 다 허용
                            .requestMatchers("/todo-api").hasAnyRole("USER", "ADMIN")
                            // /todo-api 이 주소로 들어오는 모든 것을은 C,R,U,D,메소드 상관없이 hasAnyRole()의권한이 필요하다 = 로그인이 필요하다 // 여러개면 hasAnyRole
                            .anyRequest().hasRole("ADMIN") // 다른건 모두 ADMIN이 필요하다 // 한개면 hasRole
                ) //사용 권한 체크
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //세션 사용 X
        .httpBasic(http -> http.disable()) //UI 있는 시큐리티 설정을 비활성화
                .csrf(csrf -> csrf.disable()) //CSRF 보안이 필요 X, 쿠키와 세션을 이용해서 인증을 하고 있기 때문에 발생하는 일, https://kchanguk.tistory.com/197
                .exceptionHandling(except -> {
                    except.accessDeniedHandler(new CustomAccessDeniedHandler()); //인가 // 권한이 없을 때 이렇게 처리하겠다
                    except.authenticationEntryPoint(new CustomAuthenticationEntryPoint()); //인증
                })
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
                // 필터 jst를 처리하기 위한.., 아이디와 비번으로 처리하고 싶다.class ??
                // addFilterBefore 들어올때만 필터처리
        return httpSecurity.build();
    }

    //시큐리티를 거치지 않는다. 보안과 전혀 상관없는 페이지 및 리소스

/*    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //함수형 인터페이스 람다
        WebSecurityCustomizer lamda = (web) -> web.ignoring()
                    .requestMatchers(HttpMethod.GET, "/sign-api/refresh-token");
        return lamda;
    }*/
}
