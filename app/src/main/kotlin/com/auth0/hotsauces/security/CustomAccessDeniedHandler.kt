package com.auth0.hotsauces.security

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.collections.HashMap

class CustomAccessDeniedHandler : AccessDeniedHandler {
    // Jackson JSON serializer instance
    private val objectMapper = ObjectMapper()


    override fun handle(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        accessDeniedException: AccessDeniedException?
    ) {
        val httpStatus = HttpStatus.FORBIDDEN // 403

        val data : MutableMap<String, Any?> = HashMap()
        data["timestamp"] = Date()
        data["code"] = httpStatus.value()
        data["status"] = httpStatus.name
        data["message"] = accessDeniedException?.message

        // setting the response HTTP status code
        response?.status = httpStatus.value()

        // serializing the response body in JSON
        response
            ?.outputStream
            ?.println(
                objectMapper.writeValueAsString(data)
            )
    }
}