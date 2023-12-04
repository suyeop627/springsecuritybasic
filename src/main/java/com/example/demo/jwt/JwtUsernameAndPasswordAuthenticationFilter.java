package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

//varifying credential
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final JwtConfig jwtConfig;
  private final SecretKey secretKey;
  public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfig jwtConfig, SecretKey secretKey) {
    this.authenticationManager = authenticationManager;
    this.jwtConfig = jwtConfig;
    this.secretKey = secretKey;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
                                              HttpServletResponse response) throws AuthenticationException {

    try {
      UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
          .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

      Authentication authentication = new UsernamePasswordAuthenticationToken(
          authenticationRequest.getUsername(), authenticationRequest.getPassword()
      );
      //authenticationManager는 username 존재 확인 -> password 맞는지 확인 -> 다 맞으면 해당 request는 athenticated
      Authentication authenticate = authenticationManager.authenticate(authentication);
      return authenticate;

    } catch (IOException e) {
      throw new RuntimeException(e);
    }

  }

  //attemptAuthentication()이 성공하면 실행될 메서드 -> jwt 토큰 생성 및 응답에 보냄
  @Override
  protected void successfulAuthentication(HttpServletRequest request,
                                          HttpServletResponse response,
                                          FilterChain chain,
                                          Authentication authResult) throws IOException, ServletException {

   // String key = "secure_secure_secure_secure_secure_secure_secure_secure_secure_secure_";//충분히 길고 어렵게 만들어야함

    //토큰 생성
    String token = Jwts.builder()
        .setSubject(authResult.getName())
        .claim("authorities", authResult.getAuthorities())
        .setIssuedAt(new Date())
        .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())))
        //.signWith(Keys.hmacShaKeyFor(key.getBytes()))
        .signWith(secretKey)
        .compact();
  //토큰 전달
    response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix()+token);
  }
}
