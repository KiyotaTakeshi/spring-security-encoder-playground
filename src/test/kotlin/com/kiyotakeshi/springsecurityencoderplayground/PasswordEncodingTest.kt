package com.kiyotakeshi.springsecurityencoderplayground

import com.kiyotakeshi.springsecurityencoderplayground.security.CustomEncoder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

class PasswordEncodingTest {
    private val password = "1qazxsw2"

    @Test
    @DisplayName("BCryptPasswordEncoder は実行するたびに別のHash値を生成する")
    fun `"generated different hash using different salt"`() {
        // 以下のように説明があったので試してみた
        // @ref https://www.baeldung.com/spring-security-registration-password-encoding-bcrypt
        // > BCrypt, however, will internally generate a random salt instead. This is important to understand because it means that each call will have a different result
        // > The “2a” represents the BCrypt algorithm version
        // > The “10” represents the strength of the algorithm
        // > The “Vt2ycIsscotk3diW/6RsHO” part is actually the randomly generated salt.
        // Basically, the first 22 characters are salt. The remaining part of the last field is the actual hashed version of the plain text
        // ex.) $2a$10$Vt2ycIsscotk3diW/6RsHO/xtwLJbbg9pLD59qckrCEv7xqf4A296

        val bcrypt: PasswordEncoder = BCryptPasswordEncoder()
        val bcryptEncodedPass1 = bcrypt.encode(password)
        val bcryptEncodedPass2 = bcrypt.encode(password)
        println("bcrypt encoded password1: $bcryptEncodedPass1")
        println("bcrypt encoded password2: $bcryptEncodedPass2")

        assertNotEquals(bcryptEncodedPass1, bcryptEncodedPass2)
    }

    @Test
    @DisplayName("同じ salt を使用して encode したら同じHash値になる")
    fun `"generated same hash using same salt"`() {
        val customEncoder: PasswordEncoder = CustomEncoder()
        val customEncodedPass1 = customEncoder.encode(password)
        val customEncodedPass2 = customEncoder.encode(password)
        println("custom encoded password1: $customEncodedPass1")
        println("custom encoded password1: $customEncodedPass2")

        assertEquals(customEncodedPass1, customEncodedPass2)
    }
}