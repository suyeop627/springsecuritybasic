package com.example.demo.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public enum ApplicationUserRole {
  STUDENT(new HashSet<>()),
  ADMIN(Set.of(ApplicationUserPermission.STUDENT_WRITE, ApplicationUserPermission.COURSE_WRITE, ApplicationUserPermission.COURSE_READ, ApplicationUserPermission.STUDENT_READ)),
  ADMINTRAINEE(Set.of(ApplicationUserPermission.COURSE_READ, ApplicationUserPermission.STUDENT_READ));

  private final Set<ApplicationUserPermission> permissions;

  ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
    this.permissions = permissions;
  }

  public Set<ApplicationUserPermission> getPermissions() {
    return permissions;
  }

  public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
    Set<SimpleGrantedAuthority> permissions = getPermissions().stream()//상수가 가진 멤버 set으로 permissions로 stream 생성
        .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))//set의 요소를 사용해서 SimpleGrantedAuthority를 생성
        .collect(Collectors.toSet());//set으로 반환
    permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));//반환된 set에 ROLE_role 추가
    return permissions;//{course:read, student:read, ROLE_ADMINTRAINEE}의 형식
  }
}
