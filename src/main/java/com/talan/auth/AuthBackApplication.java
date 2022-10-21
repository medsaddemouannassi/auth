package com.talan.auth;


import com.talan.auth.dto.UserDto;
import com.talan.auth.entities.Role;
import com.talan.auth.repositories.RoleRepo;
import com.talan.auth.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AuthBackApplication implements CommandLineRunner {
    @Autowired
    private UserService userService;
    @Autowired
    private RoleRepo roleRepo;

    public static void main(String[] args) {
        SpringApplication.run(AuthBackApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        roleRepo.save(Role.builder().id(1L).name("ADMIN").build());
        roleRepo.save(Role.builder().id(2L).name("USER").build());
        UserDto admin = UserDto.builder()
                .firstName("foulen")
                .lastName("ben falten")
                .email("foulen@gmail.com")
                .password("foulen123")
                .phone("22222222")
                .role(Role.builder().id(1L).build())
                .build();
        UserDto user = UserDto.builder()
                .firstName("ali")
                .lastName("ben salah")
                .email("ali@gmail.com")
                .password("ali123")
                .phone("55555555")
                .role(Role.builder().id(2L).build())
                .build();
        userService.signup(admin);
        userService.signup(user);
    }
}
