package com.kiyotakeshi.springsecurityencoderplayground.security

import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.regex.Pattern

/**
 * salt の値を固定にするとハッシュが同じになることを確認するために追加
 */
class CustomEncoder: PasswordEncoder {

    private val bcryptPattern = Pattern.compile("\\A\\$2(a|y|b)?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}")

    override fun encode(rawPassword: CharSequence?): String {
        requireNotNull(rawPassword) { "rawPassword cannot be null" }
        val notRandomSalt: String = "\$2a\$10\$AzYnC1K8/95SCW8Wktu1e."
        return BCrypt.hashpw(rawPassword.toString(), notRandomSalt)
    }


     // BCryptPasswordEncoder と同じ実装
    override fun matches(rawPassword: CharSequence?, encodedPassword: String?): Boolean {
        requireNotNull(rawPassword) { "rawPassword cannot be null" }
        if (encodedPassword == null || encodedPassword.isEmpty()) {
            return false
        }
        if (!this.bcryptPattern.matcher(encodedPassword).matches()) {
            return false
        }
        return BCrypt.checkpw(rawPassword.toString(), encodedPassword)
    }
}