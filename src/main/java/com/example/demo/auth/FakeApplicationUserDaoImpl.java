package com.example.demo.auth;

import com.example.demo.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

//로그인 시, 입력받은 id에 해당하는 user 조회
@Repository("fake") //ApplicationUserService의 @Qualifier("fake")에 사용하기 위해 빈 이름 명시
public class FakeApplicationUserDaoImpl implements ApplicationUserDAO {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public FakeApplicationUserDaoImpl(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
    return getApplicationUsers()
        .stream()
        .filter(applicationUser ->username.equals(applicationUser.getUsername()))
        .findFirst();
  }

  private List<ApplicationUser> getApplicationUsers() {
    List<ApplicationUser> applicationUsers = new ArrayList<>(
        List.of(
            new ApplicationUser(
                "annasmith",
                passwordEncoder.encode("0000"),
                ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                true,
                true,
                true,
                true
            ),
            new ApplicationUser(
                "linda",
                passwordEncoder.encode("0000"),
                ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true
            ),
            new ApplicationUser(
                "tom",
                passwordEncoder.encode("0000"),
                ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
                true,
                true,
                true,
                true
            )
        )
    );
    return applicationUsers;
  }
}
