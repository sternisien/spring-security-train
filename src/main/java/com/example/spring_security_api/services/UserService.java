package com.example.spring_security_api.services;

import com.example.spring_security_api.configuration.SecurityConfig;
import com.example.spring_security_api.entities.User;
import com.example.spring_security_api.repositories.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

  private final UserRepository userRepository;
  private final AuthenticationManager authenticationManager;

  private final BCryptPasswordEncoder encoder;
  private final JwtService jwtService;

  public UserService(
      UserRepository userRepository,
      AuthenticationManager authenticationManager,
      BCryptPasswordEncoder encoder,
      JwtService jwtService) {
    this.userRepository = userRepository;
    this.authenticationManager = authenticationManager;
    this.encoder = encoder;
    this.jwtService = jwtService;
  }

  public User create(User user) {
    user.setPassword(encoder.encode(user.getPassword()));
    return userRepository.save(user);
  }

  /**
   * Cette fonction permet de vérifier si l'utilisateur est existant en base de données en utilisant
   * la configuration dans la classe {@link SecurityConfig} utilisant la fonction {@link
   * SecurityConfig#authProvider()}
   *
   * @return
   */
  public String verify(User user) {

    // utilise la config definit dans SecurityConfig#authProvider();
    Authentication auth =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

    return auth.isAuthenticated() ? jwtService.generateToken(user.getUsername()) : "Fail";
  }
}
