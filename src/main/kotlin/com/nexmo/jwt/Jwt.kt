/*
 * Copyright (c) 2011-2019 Nexmo Inc
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
package com.nexmo.jwt

import java.nio.file.Files
import java.nio.file.Path
import java.util.*
import kotlin.collections.LinkedHashMap

/**
 * Class representing a JWT for interacting with the Nexmo API.
 */
class Jwt(val applicationId: String, val privateKeyContents: String, val claims: Map<String, Any>) {
    val issuedAt: Date by DateClaimDelegate()
    val jti: String by claims
    val notBefore: Date by DateClaimDelegate()
    val expiresAt: Date by DateClaimDelegate()
    val sub: String by claims

    /**
     * Generate a JSON Web Signature from the JWT's properties.
     */
    fun generate(jwtGenerator: JwtGenerator = JwtGenerator()): String {
        return jwtGenerator.generate(this)
    }

    class Builder(
        private var applicationId: String = "",
        private var privateKeyContents: String = "",
        private var claims: MutableMap<String, Any> = LinkedHashMap()
    ) {
        /**
         * Set the application id.
         */
        fun applicationId(applicationId: String) = apply { this.applicationId = applicationId }

        /**
         * Set the private key contents.
         */
        fun privateKeyContents(privateKeyContents: String) = apply { this.privateKeyContents = privateKeyContents }

        /**
         * Set the private key path.
         */
        fun privateKeyPath(privateKeyPath: Path) = privateKeyContents(String(Files.readAllBytes(privateKeyPath)))

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
        fun issuedAt(iat: Date) = addClaim("iat", iat)

        /**
         * Set the JWT ID (jti) claim.
         */
        fun id(jti: String) = addClaim("jti", jti)

        /**
         * Set the not before (nbf) claim.
         */
        fun notBefore(nbf: Date) = addClaim("nbf", nbf)

        /**
         * Set the expiration (exp) claim.
         */
        fun expiresAt(exp: Date) = addClaim("exp", exp)

        /**
         * Set the subject (sub) claim.
         */
        fun subject(subject: String) = addClaim("sub", subject)

        /**
         * Build the JWT using the stored builder parameters.
         */
        fun build(): Jwt {
            validate()
            return Jwt(applicationId, privateKeyContents, claims)
        }

        private fun validate() {
            if (applicationId == "" && privateKeyContents == "") throw IllegalStateException("Both an Application ID and Private Key are required.")
            if (applicationId == "") throw IllegalStateException("Application ID is required.")
            if (privateKeyContents == "") throw IllegalStateException("Private Key is required.")
        }
    }

    companion object {
        /**
         * Instantiate a new Builder for building Jwt objects.
         */
        @JvmStatic
        fun builder() = Builder()
    }
}