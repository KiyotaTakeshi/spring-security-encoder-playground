package com.kiyotakeshi.springsecurityencoderplayground

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping
class SampleController {

    @GetMapping("/public")
    fun getPublicResource(): String {
        return "this resource is public"
    }

    @GetMapping("/private")
    fun getPrivateResource(): String {
        return "this resource is private"
    }
}