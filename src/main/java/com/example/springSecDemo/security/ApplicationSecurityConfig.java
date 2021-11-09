package com.example.springSecDemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.concurrent.TimeUnit;

import static com.example.springSecDemo.security.ApplicationUserPermission.*;
import static com.example.springSecDemo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //allows method level authorization
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http  //see commented section below for explanation
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()   //since I'm not actually creating somehting where real reqs will be sent, I don't need csrf
                .authorizeRequests()
                // ¡¡¡order of the antMatchers does matter!!!
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //can be accessed by anyone
                .antMatchers("/api/**").hasRole(STUDENT.name()) //can only be accessed by students
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())  //Commented out due to adding auth at the method level
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())  //roles are defined within user config located below
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(7)) // default to 2 weeks in session
                    .key("somethingverysecured")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me") //copied from inspect
                    .logoutSuccessUrl("/login")
                ;
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
                .authorities(ADMIN.getGrantedAuthorities()) //this line of code does the exact same as the prev, just in a different way.
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
