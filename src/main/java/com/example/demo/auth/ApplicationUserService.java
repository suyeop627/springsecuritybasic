package com.example.demo.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
//db에서 정보를 fetch하는 역할
@Service
public class ApplicationUserService implements UserDetailsService {

  private final ApplicationUserDAO applicationUserDAO;
  @Autowired
  //@Qualifier("beanName") 같은 타입의 bean이 다수 존재할 때, 특정 빈을 선택해서 주입받도록 명시적으로 작성하기위한 annotation
  public ApplicationUserService(@Qualifier("fake") ApplicationUserDAO applicationUserDAO) {
    this.applicationUserDAO = applicationUserDAO;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return applicationUserDAO
        .selectApplicationUserByUsername(username)
        .orElseThrow(() ->
            new UsernameNotFoundException(String.format("Username %s not found", username)));
  }
}
