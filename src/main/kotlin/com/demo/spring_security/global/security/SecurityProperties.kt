package com.demo.spring_security.global.security

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "security")
class SecurityProperties(
    val jwtSecretKey: String,
    val jwtRole: String,
    val securityRole: String,
    val basicRole: String,
    val basicUser: String,
    val basicPassword: String
)