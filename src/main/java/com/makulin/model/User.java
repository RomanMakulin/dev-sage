package com.makulin.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String login;

    private String name;

    private String email;

    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    private String password;

}
