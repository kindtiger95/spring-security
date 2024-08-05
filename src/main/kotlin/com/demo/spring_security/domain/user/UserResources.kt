package com.demo.spring_security.domain.user

class UserResources {
    class Request {
        data class UserLogin(
            val userId: String,
            val userPassword: String
        )
    }
    data class User(
        val userId: String,
        val userPassword: String,
        val id: Long,
        val username: String,
    ) {
        var token: String? = null
    }
}