package com.demo.spring_security.global.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import java.util.*
import javax.crypto.SecretKey

private const val USER_ID = "userId"
private const val USER_NAME = "userName"

@Component
class JwtUtility(securityProperties: SecurityProperties) {
    private val signKey: SecretKey = Keys.hmacShaKeyFor(securityProperties.jwtSecretKey.toByteArray(StandardCharsets.UTF_8))
    private val jwtParser: JwtParser = Jwts.parser().verifyWith(this.signKey).build()
    private val jwtRoles: String = securityProperties.jwtRole
    private val securityRole: String = securityProperties.securityRole

    fun jwtParse(jwt: String): Claims = jwtParser.parseSignedClaims(jwt).payload

    fun jwtSign(userId: Long, userName: String): String {
        val roles = if (userName == "naver") "GUEST" else this.jwtRoles
        return Jwts.builder()
            .claim(USER_ID, userId)
            .claim(USER_NAME, userName)
            .claim(this.securityRole, roles)
            .signWith(this.signKey)
            .expiration(Date(System.currentTimeMillis() + 86400000))
            .compact()
    }
}