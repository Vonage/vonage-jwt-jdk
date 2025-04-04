/*
 * Copyright 2025 Vonage
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

import org.junit.Test
import java.nio.file.Paths
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import kotlin.test.assertEquals

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"

class ClaimDelegateTest {
    private val applicationId = UUID.randomUUID()
    
    @Test
    fun `when subject property is requested the sub value is read from the claim map`() {
        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("sub" to "subject"))
            .build()

        assertEquals("subject", jwt.subject)
    }

    @Test
    fun `when id property is requested the jti value is read from the claim map`() {
        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("jti" to "id"))
            .build()

        assertEquals("id", jwt.id)
    }

    @Test
    fun `when issuedAt property is requested the iat value is read from the claim map`() {
        val now = Instant.now()
        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("iat" to now))
            .build()

        assertEquals(now.truncatedTo(ChronoUnit.SECONDS), jwt.issuedAt)
    }

    @Test
    fun `when expiresAt property is requested the exp value is read from the claim map`() {
        val now = Instant.now()
        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("exp" to now))
            .build()

        assertEquals(now.truncatedTo(ChronoUnit.SECONDS), jwt.expiresAt)
    }

    @Test
    fun `when notBefore property is requested the nbf value is read from the claim map`() {
        val now = Instant.now()
        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("nbf" to now))
            .build()

        assertEquals(now.truncatedTo(ChronoUnit.SECONDS), jwt.notBefore)
    }
}