/*
 * Copyright 2023 Vonage
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.vonage.jwt

import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import java.time.Instant
import java.time.ZonedDateTime
import java.util.*
import kotlin.collections.LinkedHashMap

/**
 * Produce a Vonage-compliant JWS from a JWT.
 */
class JwtGenerator(private val keyConverter: KeyConverter = KeyConverter()) {
    /**
     * Generate a token from a Jwt.
     */
    fun generate(jwt: Jwt): String {
        var jwtBuilder = Jwts.builder()
            .header().add("type", "JWT").and()
            .claims().add("application_id", jwt.applicationId)
            .add(fixClaims(jwt.claims)).and()

        if (jwt.privateKeyContents.isNotBlank()) {
            val privateKey = keyConverter.privateKey(jwt.privateKeyContents)
            jwtBuilder = jwtBuilder.signWith(privateKey, Jwts.SIG.RS256)
        }
        return jwtBuilder.compact()
    }

    private fun fixClaims(claims: Map<String, Any>) : Map<String, Any> {
        val normalClaims = LinkedHashMap<String, Any>()
        normalClaims.putAll(claims)
        val timeKeys = listOf("iat", "exp", "nbf")
        val convertedClaims = claims.filter { it.key in timeKeys && it.value is ZonedDateTime }
            .mapValues { (it.value as ZonedDateTime).toEpochSecond() }
        normalClaims.putAll(convertedClaims)
        normalClaims.putIfAbsent("iat", Instant.now().epochSecond)
        normalClaims.putIfAbsent("jti", UUID.randomUUID().toString())
        return normalClaims
    }
}
