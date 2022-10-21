package com.talan.auth.services;

import com.talan.auth.dto.UserDto;

public interface UserService {
    public UserDto signup(UserDto userDto);
    public UserDto getUserById(Long userId);
    public UserDto getUserByEmail(String email);
}
