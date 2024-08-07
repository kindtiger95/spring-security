package com.demo.spring_security.global.security

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import com.demo.spring_security.global.common.BaseResponse
import com.demo.spring_security.global.common.ErrorCode

class CustomAuthenticationEntryPoint(private val objectMapper: ObjectMapper) : AuthenticationEntryPoint {
    override fun commence(
        request: HttpServletRequest, response: HttpServletResponse,
        authException: AuthenticationException?
    ) {
        val exception = request.getAttribute("exception") as? String
        val unauthorized: ErrorCode = ErrorCode.UNAUTHORIZED
        if (exception == unauthorized.code) {
            response.apply {
                this.contentType = "application/json;charset=UTF-8"
                this.status = unauthorized.httpCode
            }
            val json = objectMapper.writeValueAsString(BaseResponse(unauthorized, unauthorized.message))
            response.writer.print(json)
        }
    }
}