package com.demo.spring_security.global.filter

import com.demo.spring_security.global.common.ErrorCode
import com.demo.spring_security.global.security.JwtAuthenticationToken
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter

private const val AUTHORIZATION_HEADER = "Authorization"
private const val BEARER_PREFIX = "Token "

class JwtFilter(private val authenticationManager: AuthenticationManager) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        getToken(request)?.let {
            try {
                val authentication = authenticationManager.authenticate(JwtAuthenticationToken(it))
                SecurityContextHolder.getContext().authentication = authentication
            } catch (authenticationException: AuthenticationException) {
                SecurityContextHolder.clearContext()
                request.setAttribute("exception", ErrorCode.INTERNAL_SERVER_ERROR.code)
            }
        }
        filterChain.doFilter(request, response)
    }

    /*********************************** Private Function ***********************************/
    private fun getToken(request: HttpServletRequest): String? {
        val authHeader = request.getHeader(AUTHORIZATION_HEADER)
        return when {
            authHeader == null -> {
                request.setAttribute("exception", ErrorCode.UNAUTHORIZED.code)
                null
            }
            authHeader.startsWith(BEARER_PREFIX) -> authHeader.substring(BEARER_PREFIX.length)
            else -> {
                request.setAttribute("exception", ErrorCode.UNAUTHORIZED.code)
                null
            }
        }
    }
}