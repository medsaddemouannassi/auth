package com.talan.auth.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.talan.auth.dto.UserDto;
import com.talan.auth.entities.Role;
import com.talan.auth.services.UserService;
import com.talan.auth.util.JWTUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    //    Sign Up
    @SuppressWarnings("rawtypes")
	@PostMapping("signup")
    public ResponseEntity signup(@RequestBody UserDto userDto) {
        UserDto user = userService.signup(userDto);
        if (user == null)
            return new ResponseEntity<>("Cette adresse e-mail est déjà utilisée", HttpStatus.NOT_ACCEPTABLE);
        return new ResponseEntity<>(user, HttpStatus.CREATED);
    }

    //    Get user by Id
    @GetMapping("{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long userId) {
        if (userService.getUserById(userId) == null)
            return new ResponseEntity<>(userService.getUserById(userId), HttpStatus.NO_CONTENT);
        return new ResponseEntity<>(userService.getUserById(userId), HttpStatus.OK);
    }

    //    Get new access token
    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(JWTUtil.PREFIX)) {
            try {
                String refresh_token = authorizationHeader.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET.getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String email = decodedJWT.getSubject();
                UserDto user = userService.getUserByEmail(email);
                List<Role> roles = new ArrayList<>();
                roles.add(user.getRole());
                String access_token = JWT.create()
                        .withSubject(user.getEmail())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", roles.stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
            }
        }
    }


}
