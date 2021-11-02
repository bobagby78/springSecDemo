package com.example.springSecDemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springSecDemo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http  //see commented section below for explanation
                .csrf().disable() //TODO: learn this later
                .authorizeRequests()
                // ¡¡¡order of the antMatchers does matter!!!
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //can be accessed by anyone
                .antMatchers("/api/**").hasRole(STUDENT.name()) //can only be accessed by students
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())  //roles are defined within user config
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }
    /*
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()    THIS SETS UP AUTH
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() THIS IS ESSENTIALLY A WHITELIST- ALL RESOURCES CAN BE ACCESSED BY ANY USER
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) ANY RESOURCE IN THE API EXTENSION CAN ONLY BE ACCESSED BY STUDENTS
                .anyRequest() ALL REQUESTS...
                .authenticated()  ... MUST BE AUTHED
                .and()  ...
                .httpBasic();  ...USING BASE 64 (?) AUTH
    }
    */
    @Override
    @Bean
    public UserDetailsService userDetailsService()  {

        UserDetails juanValdezUser = User.builder()
                .username("juanvaldez")
                .password(passwordEncoder.encode("password"))
//                .roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password"))
//                .roles(ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password"))
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .roles(ApplicationUserRole.ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .build();

        return new InMemoryUserDetailsManager(
                juanValdezUser,
                lindaUser,
                tomUser
        );
    }
}
