package com.talan.auth.services.impl;

import com.talan.auth.dto.UserDto;
import com.talan.auth.entities.User;
import com.talan.auth.helpers.ModelMapperConverter;
import com.talan.auth.repositories.RoleRepo;
import com.talan.auth.repositories.UserRepo;
import com.talan.auth.services.UserService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }

    //    Sign up
    @Override
    public UserDto signup(UserDto userDto) {
        if (this.getUserByEmail(userDto.getEmail()) != null) return null;
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        userDto.setRole(roleRepo.findById(userDto.getRole().getId()).orElse(null));
        return ModelMapperConverter.map(userRepo.save(ModelMapperConverter.map(userDto, User.class)), UserDto.class);
    }

    //    Get user by id
    @Override
    public UserDto getUserById(Long userId) {
        return ModelMapperConverter.map(userRepo.findById(userId), UserDto.class);
    }

    //    Get user by email
    @Override
    public UserDto getUserByEmail(String email) {
        try {
            return ModelMapperConverter.map(userRepo.findByEmail(email), UserDto.class);
        } catch (NullPointerException e) {
            return null;
        }
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserDto user = this.getUserByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(user.getRole().getName()));
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
    }
}
