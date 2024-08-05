package com.demo.spring_security.global.security

import com.demo.spring_security.domain.user.UserResources
import io.jsonwebtoken.Claims
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class JwtAuthenticationToken : AbstractAuthenticationToken {
    private lateinit var credentials: String
    private lateinit var principal: Claims
    lateinit var user: UserResources.User

    constructor(jsonWebToken: String) : super(null) {
        this.details = jsonWebToken
        this.isAuthenticated = false
    }

    constructor(
        principal: Claims,
        credentials: String,
        authorities: Collection<GrantedAuthority>
    ) : super(authorities) {
        this.principal = principal
        this.credentials = credentials
        super.setAuthenticated(true)
    }

    override fun getCredentials() = this.credentials

    override fun getPrincipal() = this.principal

    fun isUserInitialized() = this::user.isInitialized
}