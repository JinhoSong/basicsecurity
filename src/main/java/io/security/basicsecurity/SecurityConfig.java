package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // 인가 설정
                .anyRequest().authenticated(); // 모든 request에 대해 인증를 받도록 설정
        http    // 인증 정책
                .formLogin() // form 방식으로 인증 받도록 설정한다.
               // .loginPage("/loginPage") // 여기는 누구나 접근이 가능하도록 인가 설정해야된다.
                .defaultSuccessUrl("/")// 성공시 이동될 url
                .failureUrl("/login")
                .usernameParameter("userId") // form 값이랑 같아야 한다.
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        // authentication : 인증 성공시 최종 결과
//                        // 구체적인 로직 구현
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : "+exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
                .permitAll();


    }
}
