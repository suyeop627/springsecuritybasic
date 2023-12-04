package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity //애플리케이션에 필요한 설정을 할 수 있음
@EnableGlobalMethodSecurity(prePostEnabled = true) //메서드레벨에서 보안 활성화. @PreAuthorize 나  @PostAuthorize를 활성화 시킴
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;
  private final ApplicationUserService applicationUserService;

  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
    this.passwordEncoder = passwordEncoder;
    this.applicationUserService = applicationUserService;
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
        .formLogin()
          .loginPage("/login").permitAll()
          .defaultSuccessUrl("/courses",true)
          .passwordParameter("password")//로그인 form의 input name 변경하고싶을때 설정.
          .usernameParameter("username") //로그인 form의 input name 변경하고싶을때 설정.
        .and()
        .rememberMe()
          .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))//유효기간으로 정할 값(초단위)  -21일간 저장시킬 예정
          .key("somethindverysecured")//remember me 토큰 생성할때 사용되는 키
          .rememberMeParameter("remember-me") //로그인 form의 input name 변경하고싶을때 설정.
        .and()
        .logout()//로그아웃 설정 시작
          .logoutUrl("/logout")//로그아웃 요청보낼 url
        //csrf protection이 활성화된 상태면 post로 로그아웃 요청 보내야하는데, 굳이 get으로 로그아웃 할 경우의 설정
          .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
          .clearAuthentication(true)//사용자 인증정보 삭제
          .invalidateHttpSession(true)//세션 무효화
          .deleteCookies("JSESSIONID", "remeber-me")//쿠키 삭제
          .logoutSuccessUrl("/login");//로그아웃 성공시 redirection될 url

  }
//AuthenticationManagerBuilder의 authenticationProvider에 daoAuthenticationProvider를 추가함
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(daoAuthenticationProvider());
  }

  //사용자 인증을 위해 사용자 정보와 비밀번호를 저장소에서 가져오는데 사용됨
  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider(){
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder);//비밀번호 인증방식
    provider.setUserDetailsService(applicationUserService);//사용자 정보 가져올때 사용할 userDetailsService
    return provider;
  }

// auth packge에서 대체함
  /*
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
        .roles(ApplicationUserRole.ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
        .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
        .build();
    return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
  }
*/

}

