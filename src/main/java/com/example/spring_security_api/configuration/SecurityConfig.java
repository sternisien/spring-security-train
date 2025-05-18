package com.example.spring_security_api.configuration;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Autowired private UserDetailsService userDetailsService;

  @Autowired private JwtFilter jwtFilter;

  /**
   * Par défaut si je ne met pas cette configuration je peux accéder au form localhost:8080 , une
   * fois mis en place je suis bloqué car je dois etre authentifié pour chauque requete
   *
   * @param http
   * @return
   * @throws Exception
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable);
    http.authorizeHttpRequests(
        request ->
            request
                .requestMatchers("/users/register", "/users/login")
                .permitAll()
                .anyRequest()
                .authenticated());
    // nav response formulaire
    http.formLogin(Customizer.withDefaults());
    // Rest client response (postman)
    http.httpBasic(Customizer.withDefaults());
    // Pour ne gérer aucun état -> requier une authentification à chaque requete
    http.sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // cette ligne active l'authentification par JWT et vérifie le token à chaque requete
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  /**
   * Permet de customiser le service gérant l'authentification des utilisateurs. Par défaut, Spring
   * utilise son propre service d'authentification d'utilisateur en se basant sur le
   * fichier.properties
   *
   * @return
   */
  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user =
        User.withDefaultPasswordEncoder().username("test").password("tldko").roles("USER").build();
    UserDetails user2 =
        User.withDefaultPasswordEncoder()
            .username("test2")
            .password("tldka")
            .roles("ADMIN")
            .build();
    return new InMemoryUserDetailsManager(List.of(user, user2));
  }

  /**
   * Permet de configurer l'encoder qui permet de hasher le mot passe utilisateur. Le strength
   * correspond à la complexité du hashage, plus le chiffre est élevé plus l'encryption sera longue
   *
   * @return L'encoder
   */
  @Bean
  public BCryptPasswordEncoder encoder() {
    return new BCryptPasswordEncoder(12);
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
      throws Exception {
    return configuration.getAuthenticationManager();
  }

  /**
   * Configuration permettant de s'authentifier via une base de données. Désactive la partie
   * inMemory lorsque ceci est mis en place.
   *
   * @return
   */
  @Bean
  public AuthenticationProvider authProvider() {
    DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setPasswordEncoder(encoder());
    daoAuthenticationProvider.setUserDetailsService(userDetailsService);
    return daoAuthenticationProvider;
  }
}
