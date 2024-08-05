package com.demo.spring_security.global.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class GlobalConfig {
    @Bean
    fun objectMapper(): ObjectMapper = ObjectMapper().registerKotlinModule().findAndRegisterModules()
}