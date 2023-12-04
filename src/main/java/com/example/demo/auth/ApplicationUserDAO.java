package com.example.demo.auth;

import java.util.Optional;
//로그인 시, 입력받은 id로 정보 조회하는 기능 수행
public interface ApplicationUserDAO{

  Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
