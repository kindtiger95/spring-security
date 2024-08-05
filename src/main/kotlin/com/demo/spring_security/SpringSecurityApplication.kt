package com.demo.spring_security

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan(basePackages = ["com.demo.spring_security"])
class SpringSecurityApplication

fun main(args: Array<String>) {
	runApplication<SpringSecurityApplication>(*args)
}
