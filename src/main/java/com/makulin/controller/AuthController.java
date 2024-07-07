package com.makulin.controller;

import com.makulin.model.Token;
import com.makulin.model.User;
import com.makulin.service.auth.UserAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UserAuthService userAuthService;

    public AuthController(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @PostMapping("/registration")
    public ResponseEntity<User> register(@RequestBody User user) {
        return ResponseEntity.ok(userAuthService.registration(user));
    }

    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody User user) {
        Token token = userAuthService.login(user).getBody();
        ResponseCookie cookie = ResponseCookie.from("JWT", token.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(3600)
                .build();

        log.info("User: {} login success", user.getLogin());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<Token> refresh(@RequestParam String refreshToken) {
        return userAuthService.refresh(refreshToken);
    }


}
