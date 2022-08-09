/*
 * Copyright 2022 Vonage
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
import io.jsonwebtoken.SignatureAlgorithm
import java.time.Instant
import java.time.ZonedDateTime
import java.util.*

/**
 * Produce a Vonage-compliant JWS from a JWT.
 */
class JwtGenerator(private val keyConverter: KeyConverter = KeyConverter()) {
    /**
     * Generate a token from a Jwt.
     */
    fun generate(jwt: Jwt): String {
        var jwtBuilder = Jwts.builder()
            .setHeaderParam("type", "JWT")
            .claim("application_id", jwt.applicationId)
            .addClaims(jwt.claims)

        addRequiredNonExistentClaims(jwt.claims, jwtBuilder)
        convertUserSuppliedDateClaimsToEpoch(jwt.claims, jwtBuilder)

        if (jwt.privateKeyContents.isNotBlank()) {
            val privateKey = keyConverter.privateKey(jwt.privateKeyContents)
            jwtBuilder = jwtBuilder.signWith(privateKey, SignatureAlgorithm.RS256)
        }
        return jwtBuilder.compact()
    }

    private fun addRequiredNonExistentClaims(claims: Map<String, Any>, jwtBuilder: JwtBuilder) {
        if (!claims.containsKey("iat")) jwtBuilder.claim("iat", Instant.now().epochSecond)
        if (!claims.containsKey("jti")) jwtBuilder.claim("jti", UUID.randomUUID().toString())
    }

    private fun convertUserSuppliedDateClaimsToEpoch(claims: Map<String, Any>, jwtBuilder: JwtBuilder) {
        convertZonedDateTimesToLong(claims, jwtBuilder, "iat", "exp", "nbf")
    }

    private fun convertZonedDateTimesToLong(claims: Map<String, Any>, builder: JwtBuilder, vararg keys: String) {
        builder.addClaims(
            claims.filter { it.key in keys && it.value is ZonedDateTime }
                .mapValues { (it.value as ZonedDateTime).toEpochSecond() }

        )
    }
}
