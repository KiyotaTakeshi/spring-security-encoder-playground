package com.kiyotakeshi.springsecurityencoderplayground

import org.jetbrains.annotations.NotNull
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.Id

@Entity
data class User(

    @Id
    val id: Long? = null,

    @NotNull
    val email: String = "",

    @NotNull
    val password: String = "",

    @NotNull
    val name: String = "",
)
