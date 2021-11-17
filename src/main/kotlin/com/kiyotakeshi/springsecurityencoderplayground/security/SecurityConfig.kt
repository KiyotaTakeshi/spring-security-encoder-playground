package com.kiyotakeshi.springsecurityencoderplayground.security

import com.kiyotakeshi.springsecurityencoderplayground.UserRepository
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

@EnableWebSecurity
class SecurityConfig(
    private val userRepository: UserRepository
) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .mvcMatchers("/login","/public").permitAll()
            .anyRequest().authenticated()
            .and()
            .csrf().disable()
            .formLogin()
            .loginProcessingUrl("/login")
            .usernameParameter("email")
            .passwordParameter("pass")
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(SampleAuthenticationEntryPoint())
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(SampleUserDetailsService(userRepository))
            .passwordEncoder(BCryptPasswordEncoder())
    }

}