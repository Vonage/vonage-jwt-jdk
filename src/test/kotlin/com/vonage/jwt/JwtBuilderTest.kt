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

import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Paths
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit
import java.time.temporal.Temporal
import java.time.temporal.TemporalUnit
import java.util.*
import kotlin.test.assertEquals

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"

class JwtBuilderTest {
    private val applicationId = UUID.randomUUID()
    private lateinit var builder: Jwt.Builder

    @Before
    fun setUp() {
        builder = Jwt.builder()
    }

    @Test(expected = IllegalStateException::class)
    fun `when application id and private key is missing an IllegalStateException is thrown upon build`() {
        builder.build()
    }

    @Test(expected = IllegalStateException::class)
    fun `when application id is missing an IllegalStateException is thrown upon build`() {
        builder.privateKeyPath(Paths.get(PRIVATE_KEY_PATH)).build()
    }

    @Test(expected = IllegalStateException::class)
    fun `when private key is missing an IllegalStateException is thrown upon build`() {
        builder.applicationId(applicationId).build()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `when application id is not a UUID an IllegalArguementException is thrown`() {
        builder.applicationId("application-id")
    }

    @Test
    fun `when application id and private key are provided jwt is built with them`() {
        val jwt = builder.applicationId(applicationId)
            .privateKeyPath(PRIVATE_KEY_PATH).build()

        assertEquals(applicationId, jwt.applicationId)
        assertEquals(File(PRIVATE_KEY_PATH).readText(), jwt.privateKeyContents)
    }

    @Test
    fun `when a map of claims is given the jwt is built with them`() {
        val jwt = builderWithRequiredFields()
            .claims(mapOf("foo" to "bar", "baz" to "bat"))
            .build()

        assertApplicationId(3, jwt)
        assertEquals("bar", jwt.claims["foo"])
        assertEquals("bat", jwt.claims["baz"])
    }

    @Test
    fun `when a map of claims is given but an existing map exists the jwt is built with all of them`() {
        val jwt = builderWithRequiredFields()
            .claims(mapOf("foo" to "bar"))
            .claims(mapOf("baz" to "bat"))
            .build()

        assertApplicationId(3, jwt)
        assertEquals("bar", jwt.claims["foo"])
        assertEquals("bat", jwt.claims["baz"])
    }

    @Test
    fun `when a multiple claims are given the jwt is built with all of them`() {
        val jwt = builderWithRequiredFields()
            .addClaim("foo", "bar")
            .addClaim("baz", "bat")
            .build()

        assertApplicationId(3, jwt)
        assertEquals("bar", jwt.claims["foo"])
        assertEquals("bat", jwt.claims["baz"])
    }

    @Test
    fun `when a claim is given but an existing map exists the jwt is built with all of them`() {
        val jwt = builderWithRequiredFields()
            .claims(mapOf("foo" to "bar"))
            .addClaim("baz", "bat")
            .build()

        assertApplicationId(3, jwt)
        assertEquals("bar", jwt.claims["foo"])
        assertEquals("bat", jwt.claims["baz"])
    }

    @Test
    fun `when issued at is given the jwt is built with it`() {
        val now = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)
        val jwt = builderWithRequiredFields()
            .issuedAt(now)
            .build()

        assertApplicationId(2, jwt)
        assertEquals(now, jwt.issuedAt.atZone(ZoneId.systemDefault()))
    }

    @Test
    fun `when id is given the jwt is built with it`() {
        val jwt = builderWithRequiredFields()
            .id("id")
            .build()

        assertApplicationId(2, jwt)
        assertEquals("id", jwt.id)
    }

    @Test
    fun `when not before is given the jwt is built with it`() {
        val now = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)
        val jwt = builderWithRequiredFields()
            .notBefore(now)
            .build()

        assertApplicationId(2, jwt)
        assertEquals(now, jwt.notBefore.atZone(ZoneId.systemDefault()))
    }

    @Test
    fun `when expires at is given the jwt is built with it`() {
        val now = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS)
        val jwt = builderWithRequiredFields()
            .expiresAt(now)
            .build()

        assertApplicationId(2, jwt)
        assertEquals(now, jwt.expiresAt.atZone(ZoneId.systemDefault()))
    }

    @Test
    fun `when subject is given the jwt is built with it`() {
        val jwt = builderWithRequiredFields()
            .subject("subject")
            .build()

        assertApplicationId(2, jwt)
        assertEquals("subject", jwt.subject)
    }

    @Test
    fun `when unsigned is true private key is not required`() {
        assertNotNull(builder.applicationId(applicationId).unsigned().build());
    }

    private fun builderWithRequiredFields() = builder.applicationId(applicationId)
        .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))

    private fun assertApplicationId(size: Int, jwt: Jwt) {
        assertEquals(size, jwt.claims.size)
        assertEquals(applicationId.toString(), jwt.claims[Jwt.APPLICATION_ID_CLAIM] as String)
    }
}