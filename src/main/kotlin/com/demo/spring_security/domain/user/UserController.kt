package com.demo.spring_security.domain.user

import com.demo.spring_security.global.security.JwtAuthenticationToken
import com.demo.spring_security.global.security.JwtUtility
import io.jsonwebtoken.Claims
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException

@RestController
@RequestMapping("/api")
class UserController(private val jwtUtility: JwtUtility) {
    // users는 security에 걸려있지 않으므로 인증 없이 통과한다.
    @PostMapping("/users/login")
    fun login(@RequestBody request: UserResources.Request.UserLogin): UserResources.User {
        val user = users.firstOrNull { it.userId == request.userId && it.userPassword == request.userPassword }
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND)
        user.token = jwtUtility.jwtSign(user.id, user.username)
        return user
    }

    @GetMapping("/user/me")
    fun me(): UserResources.User {
        return getCurrentUser() ?: throw ResponseStatusException(HttpStatus.NOT_FOUND)
    }

    private fun getCurrentUser(): UserResources.User? {
        val authentication = SecurityContextHolder.getContext().authentication as? JwtAuthenticationToken
            ?: return null
        if (authentication.isUserInitialized()) {
            return authentication.user
        }
        val claims: Claims = authentication.getPrincipal()
        val userId = (claims["userId"] as? Int)?.toLong() ?: throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "can't find user id info from token."
        )
        val userName = claims["userName"] as? String ?: throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "can't find user name info from token."
        )
        val user: UserResources.User = users.firstOrNull { it.id == userId } ?: return null
        if (user.username != userName) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "can't match username.")
        }
        authentication.user = user
        return user
    }
}