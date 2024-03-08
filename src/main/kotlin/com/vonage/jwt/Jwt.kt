/*
 * Copyright 2024 Vonage
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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.ZonedDateTime
import javax.crypto.spec.SecretKeySpec

/**
 * Class representing a JWT for interacting with the Vonage API. Construct using Jwt.builder
 */
class Jwt private constructor(val applicationId: String, val privateKeyContents: String, var claims: Map<String, Any>) {
    val issuedAt: ZonedDateTime by DateClaimDelegate()
    val id: String by StringClaimDelegate()
    val notBefore: ZonedDateTime by DateClaimDelegate()
    val expiresAt: ZonedDateTime by DateClaimDelegate()
    val subject: String by StringClaimDelegate()

    /**
     * Generate a JSON Web Signature from the JWT's properties.
     */
    @JvmOverloads
    fun generate(jwtGenerator: JwtGenerator = JwtGenerator()): String {
        return jwtGenerator.generate(this)
    }

    class Builder(
        private var applicationId: String = "",
        private var privateKeyContents: String = "",
        private var signed: Boolean = true,
        private var claims: MutableMap<String, Any> = mutableMapOf()
    ) {
        /**
         * Set the application id.
         */
        fun applicationId(applicationId: String) = apply { this.applicationId = applicationId }

        /**
         * Makes this token unsigned, so that private key is not required.
         */
        fun unsigned() = apply { signed = false }

        /**
         * Set the private key contents.
         */
        fun privateKeyContents(privateKeyContents: String) = apply {
            this.privateKeyContents = privateKeyContents
            signed = privateKeyContents.isNotBlank()
        }

        /**
         * Set the private key path.
         */
        fun privateKeyPath(privateKeyPath: Path) = privateKeyContents(String(Files.readAllBytes(privateKeyPath)))

        /**
         * Set the private key path.
         */
        fun privateKeyPath(privateKeyPath: String) = privateKeyPath(Paths.get(privateKeyPath))

        /**
         * Add multiple claims by putting all entries in a claim map to the existing claim map.
         */
        fun claims(claims: Map<String, Any>) = apply { this.claims.putAll(claims) }

        /**
         * Add a single claim to the map of claims.
         */
        fun addClaim(key: String, value: Any) = apply { this.claims[key] = value }

        /**
         * Set the issued at (iat) claim.
         */
        fun issuedAt(iat: ZonedDateTime) = addClaim("iat", iat)

        /**
         * Set the JWT ID (jti) claim.
         */
        fun id(jti: String) = addClaim("jti", jti)

        /**
         * Set the not before (nbf) claim.
         */
        fun notBefore(nbf: ZonedDateTime) = addClaim("nbf", nbf)

        /**
         * Set the expiration (exp) claim.
         */
        fun expiresAt(exp: ZonedDateTime) = addClaim("exp", exp)

        /**
         * Set the subject (sub) claim.
         */
        fun subject(subject: String) = addClaim("sub", subject)

        /**
         * Build the JWT using the stored builder parameters.
         * @throws IllegalStateException if an application id or private key is missing.
         */
        fun build(): Jwt {
            validate()
            return Jwt(applicationId, privateKeyContents, claims)
        }

        private fun validate() {
            if (applicationId == "" && privateKeyContents == "") throw IllegalStateException("Both an Application ID and Private Key are required.")
            if (applicationId == "") throw IllegalStateException("Application ID is required.")
            if (privateKeyContents == "" && signed) throw IllegalStateException("Private Key is required for signed token.")
        }
    }

    companion object {
        /**
         * Instantiate a new Builder for building Jwt objects.
         *
         * @return A new Builder.
         */
        @JvmStatic
        fun builder() = Builder()

        /**
         * Determines whether the provided JSON Web Token was signed by a given SHA-256 HMAC secret.
         *
         * @param secret The 256-bit symmetric HMAC signature.
         * @param token The encoded JWT to check.
         *
         * @return {@code true} iff the token was signed by the secret, {@code false} otherwise.
         *
         * @since 1.1.0
         */
        @JvmStatic
        fun verifySignature(token : String, secret : String) : Boolean =
            try {
                val secretSpec = SecretKeySpec(secret.toByteArray(), "HmacSHA256")
                Jwts.parser().verifyWith(secretSpec).build().parse(token)
                true
            }
            catch (ex : SignatureException) {
                false;
            }
    }
}