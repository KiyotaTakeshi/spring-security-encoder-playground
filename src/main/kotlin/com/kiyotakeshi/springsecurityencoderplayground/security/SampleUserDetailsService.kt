package com.kiyotakeshi.springsecurityencoderplayground.security

import com.kiyotakeshi.springsecurityencoderplayground.User
import com.kiyotakeshi.springsecurityencoderplayground.UserRepository
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService

class SampleUserDetailsService(
    private val userRepository: UserRepository
): UserDetailsService{

    override fun loadUserByUsername(username: String): UserDetails? {
        val user: User? = userRepository.findByEmail(username)
        return user?.let { SampleUserDetails(user) }
    }
}

data class SampleUserDetails(val id: Long?, val email: String, val pass: String) :
    UserDetails {
    constructor(user: User) : this(user.id, user.email, user.password)

    // 認可の実装はしていないので
    override fun getAuthorities(): MutableCollection<out GrantedAuthority>? {
        return null;
    }

    override fun getPassword(): String {
        return this.pass
    }

    override fun getUsername(): String {
        return this.email
    }

    override fun isAccountNonExpired(): Boolean {
        return true;
    }

    override fun isAccountNonLocked(): Boolean {
        return true;
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true;
    }

    override fun isEnabled(): Boolean {
        return true;
    }
}
