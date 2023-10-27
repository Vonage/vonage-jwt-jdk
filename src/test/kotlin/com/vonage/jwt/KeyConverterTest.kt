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

import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.*
import kotlin.test.assertEquals

private const val PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----\n"
private const val PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----"
private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"
private const val PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----\n"
private const val PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----"
private const val PUBLIC_KEY_PATH = "src/test/resources/public.key"

class KeyConverterTest {
    val privateKeyContents = File(PRIVATE_KEY_PATH).readText()
    val publicKeyContents = File(PUBLIC_KEY_PATH).readText()

    val sanitizedPrivateKey = privateKeyContents
        .replace(PRIVATE_KEY_HEADER, "")
        .replace(PRIVATE_KEY_FOOTER, "")
        .replace("\\s".toRegex(), "")

    val sanitizedPublicKey = publicKeyContents
        .replace(PUBLIC_KEY_HEADER, "")
        .replace(PUBLIC_KEY_FOOTER, "")
        .replace("\\s".toRegex(), "")

    lateinit var keyConverter: KeyConverter

    @Before
    fun setup() {
        keyConverter = KeyConverter()
    }

    @Test
    fun `when presented with a private key string, an RsaKey is created`() {
        val key = keyConverter.privateKey(privateKeyContents)

        assertEquals("PKCS#8", key.format)
        assertEquals(sanitizedPrivateKey, Base64.getEncoder().encodeToString(key.encoded))
    }

    @Test
    fun `when presented with a sanitized private key string, an RsaKey is created`() {
        val key = keyConverter.privateKey(sanitizedPrivateKey)

        assertEquals("PKCS#8", key.format)
        assertEquals(sanitizedPrivateKey, Base64.getEncoder().encodeToString(key.encoded))
    }

    @Test
    fun `when presented with a public key string, an RsaKey is created`() {
        val key = keyConverter.publicKey(publicKeyContents)

        assertEquals("X.509", key.format)
        assertEquals(sanitizedPublicKey, Base64.getEncoder().encodeToString(key.encoded))
    }

    @Test
    fun `when presented with a sanitized public key string, an RsaKey is created`() {
        val key = keyConverter.publicKey(publicKeyContents)

        assertEquals("X.509", key.format)
        assertEquals(sanitizedPublicKey, Base64.getEncoder().encodeToString(key.encoded))
    }
}