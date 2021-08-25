package com.auth0.hotsauces.security

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.collections.HashMap

class CustomAuthenticationFailureHandler : AuthenticationFailureHandler {
    // Jackson JSON serializer instance
    private val objectMapper = ObjectMapper()

    override fun onAuthenticationFailure(
        request : HttpServletRequest,
        response : HttpServletResponse,
        exception : AuthenticationException
    ) {
        val httpStatus = HttpStatus.UNAUTHORIZED // 401

        val data : MutableMap<String, Any?> = HashMap()
        data["timestamp"] = Date()
        data["code"] = httpStatus.value()
        data["status"] = httpStatus.name
        data["message"] = exception.message

        // setting the response HTTP status code
        response.status = httpStatus.value()

        // serializing the response body in JSON
        response
            .outputStream
            .println(
                objectMapper.writeValueAsString(data)
            )
    }
}