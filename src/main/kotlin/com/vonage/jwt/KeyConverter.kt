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

import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Convert a PKCS8Encoded or X509EncodedKeySpec Key to an RsaKey
 */
class KeyConverter(private val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")) {
    fun privateKey(key: String): RSAPrivateKey =
        keyFactory.generatePrivate(privateKeySpec(sanitize(key))) as RSAPrivateKey

    fun publicKey(key: String): RSAPublicKey =
        keyFactory.generatePublic(publicKeySpec(sanitize(key))) as RSAPublicKey

    private fun sanitize(key: String) = key
        .replace(PRIVATE_KEY_HEADER, "")
        .replace(PRIVATE_KEY_FOOTER, "")
        .replace(PUBLIC_KEY_HEADER, "")
        .replace(PUBLIC_KEY_FOOTER, "")
        .replace("\\s".toRegex(), "")

    private fun decode(key: String): ByteArray = Base64.getDecoder().decode(key)
    private fun privateKeySpec(key: String) = PKCS8EncodedKeySpec(decode(key))
    private fun publicKeySpec(key: String) = X509EncodedKeySpec(decode(key))

    companion object {
        private const val PRIVATE_KEY_HEADER: String = "-----BEGIN PRIVATE KEY-----\n"
        private const val PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----"
        private const val PUBLIC_KEY_HEADER: String = "-----BEGIN PUBLIC KEY-----\n"
        private const val PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----"
    }
}
