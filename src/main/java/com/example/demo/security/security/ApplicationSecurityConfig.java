package com.example.demo.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity //애플리케이션에 필요한 설정을 할 수 있음
@EnableGlobalMethodSecurity(prePostEnabled = true) //메서드레벨에서 보안 활성화. @PreAuthorize 나  @PostAuthorize를 활성화 시킴
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        //.and()
        .csrf().disable()
        .authorizeRequests()//요청을 인가할 거
        .antMatchers("/", "index", "/css/*", "/js/*")//화이트리스트 지정을 위해 특정 경로 패턴 정의
          .permitAll() //상기 패턴은 허용함
        .antMatchers("/api/**")//api하위의 모든 것
          .hasRole(ApplicationUserRole.STUDENT.name())//지정된 uri는 STUDENT role만 접근 가능함.
        //method level에서 처리했으므로 일단 주석처리
//              .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())//antMatchers 메서드의 첫 인자로 http method넣을 수 있음.
//              .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//              .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//              .antMatchers(HttpMethod.GET, "management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
        .anyRequest()//어떤 요청이든
        .authenticated()//인증된 거
        .and()
        .httpBasic();//인증 수단은 httpBasic
  }


  @Override
  @Bean
  protected UserDetailsService userDetailsService() { //db에서 어떻게 유저를 가져오는지 정의
    UserDetails annaSmithUser = User.builder()
        .username("annasmith")
        .password(passwordEncoder.encode("0000"))
        //.roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT 로 활용됨
        .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
        .build();//UserDetails생성

    UserDetails lindaUser = User.builder()
        .username("linda")
        .password(passwordEncoder.encode("0000"))
        //.roles(ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
        .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
        .build();
    UserDetails tomUser = User.builder()
        .username("tom")
        .password(passwordEncoder.encode("0000"))
        //.roles(ApplicationUserRole.ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
        .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
        .build();
    return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
  }
}

