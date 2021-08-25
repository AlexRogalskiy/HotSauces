package com.auth0.hotsauces.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.stereotype.Component


@EnableWebSecurity
class SecurityConfig : WebSecurityConfigurerAdapter() {

    @Value("\${auth0.audience}")
    private val audience: String? = null

    @Value("\${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private val issuer: String? = null

    @Bean
    fun jwtDecoder(): JwtDecoder {
        val jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuer) as NimbusJwtDecoder
        val audienceValidator: OAuth2TokenValidator<Jwt> = AudienceValidator(audience!!)
        val withIssuer: OAuth2TokenValidator<Jwt> = JwtValidators.createDefaultWithIssuer(issuer)
        val withAudience: OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator(withIssuer, audienceValidator)
        jwtDecoder.setJwtValidator(withAudience)
        return jwtDecoder
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .mvcMatchers("/api/hotsauces/test").permitAll()
            .mvcMatchers("/api/hotsauces/count").permitAll()
            .mvcMatchers("/api/hotsauces").authenticated()
            .mvcMatchers("/api/hotsauces/*").authenticated()
            .and()
            .addFilter(bearerTokenAuthenticationFilter())
            .exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler())
            .and()
            .oauth2ResourceServer()
            .jwt()
    }

    fun bearerTokenAuthenticationFilter(): BearerTokenAuthenticationFilter {
        val filter = BearerTokenAuthenticationFilter(authenticationManagerBean())
        filter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return filter
    }

    @Bean
    fun authenticationFailureHandler() : AuthenticationFailureHandler {
        return CustomAuthenticationFailureHandler()
    }

    @Bean
    fun accessDeniedHandler(): AccessDeniedHandler? {
        return CustomAccessDeniedHandler()
    }

}