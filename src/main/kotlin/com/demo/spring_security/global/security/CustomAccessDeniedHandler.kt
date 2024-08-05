package com.demo.spring_security.global.security

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import com.demo.spring_security.global.common.BaseResponse
import com.demo.spring_security.global.common.ErrorCode

class CustomAccessDeniedHandler(private val objectMapper: ObjectMapper) : AccessDeniedHandler {

    override fun handle(
        request: HttpServletRequest, response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        val forbidden: ErrorCode = ErrorCode.FORBIDDEN
        response.apply {
            this.contentType = "application/json;charset=UTF-8"
            this.status = forbidden.httpCode
        }
        val json = objectMapper.writeValueAsString(BaseResponse(forbidden, forbidden.message))
        response.writer.print(json)
    }
}