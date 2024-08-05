package com.demo.spring_security.global.config

import com.demo.spring_security.global.filter.JwtFilter
import com.demo.spring_security.global.security.CustomAccessDeniedHandler
import com.demo.spring_security.global.security.CustomAuthenticationEntryPoint
import com.demo.spring_security.global.security.JwtProvider
import com.demo.spring_security.global.security.SecurityProperties
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val securityProperties: SecurityProperties,
    private val objectMapper: ObjectMapper,
    private val authenticationManagerBuilder: AuthenticationManagerBuilder,
    private val jwtProvider: JwtProvider
) {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        val authenticationManager = this.authenticationManagerBuilder.authenticationProvider(jwtProvider).orBuild // 인증할 때 사용할 authentication manager를 만든다.
        return http.authorizeHttpRequests {
            it.requestMatchers("/api/user/**") // /api/user/** 경로에 매칭되는 호출은
                .hasAuthority(securityProperties.jwtRole) // securityProperties.jwtRole 인가를 받은 요청만이 통과한다.
                .anyRequest() // 그 외 경로들은
                .permitAll() // 모두 허용한다.
        }
            .csrf { it.disable() }
            .cors { it.disable() }
            .httpBasic { it.disable() }
            .requestCache { it.disable() }
            .securityContext { it.disable() }
            .sessionManagement { it.disable() }
            .formLogin { it.disable() }
            .logout { it.disable() }
            .headers { it.disable() } // 이 프로젝트는 데모 프로젝트이므로 위의 필터들은 모두 disable 시켜준다.
            .addFilterAfter(
                JwtFilter(authenticationManager), // 커스텀 필터를 추가해준다. 추후에 위 필터들을 사용할 것이라면 필터 순서도 중요해진다.
                WebAsyncManagerIntegrationFilter::class.java
            )
            .exceptionHandling {
                it.authenticationEntryPoint(CustomAuthenticationEntryPoint(objectMapper)) // 인증 실패
                    .accessDeniedHandler(CustomAccessDeniedHandler(objectMapper)) // 인가 실패
            }
            .build()
    }
}