package com.makulin.service;

import com.makulin.model.User;
import org.springframework.http.ResponseEntity;

public interface UserService {
    User registration(User userDetails);
    ResponseEntity<String> login(User userDetails);
}
