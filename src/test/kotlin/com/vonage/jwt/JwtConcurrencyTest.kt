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

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.io.File
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JwtConcurrencyTest {
    private val applicationId = "00000000-0000-4000-8000-000000000000"
    private val privateKeyContents = File("src/test/resources/private.key").readText()
    private val publicKey = KeyConverter().publicKey(File("src/test/resources/public.key").readText())

    private fun generateConcurrently(jwt: Jwt, threads: Int, perThread: Int): List<String> {
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        val tasks = (1..threads).map {
            pool.submit<List<String>> {
                start.await()
                (1..perThread).map { jwt.generate() }
            }
        }
        start.countDown()
        val tokens = tasks.flatMap { it.get(60, TimeUnit.SECONDS) }
        pool.shutdown()
        return tokens
    }

    @Test
    fun `tokens generated concurrently from one jwt each have a unique id`() {
        val jwt = Jwt.builder().applicationId(applicationId).privateKeyContents(privateKeyContents).build()

        val tokens = generateConcurrently(jwt, threads = 16, perThread = 500)

        val ids = tokens.map { JWT.decode(it).id }
        assertEquals(tokens.size, ids.size)
        assertEquals(ids.size, ids.toSet().size, "jti values were reused across tokens")
    }

    @Test
    fun `tokens generated concurrently from one jwt are all valid`() {
        val jwt = Jwt.builder().applicationId(applicationId).privateKeyContents(privateKeyContents).build()
        val verifier = JWT.require(Algorithm.RSA256(publicKey as RSAPublicKey, null)).build()

        val tokens = generateConcurrently(jwt, threads = 16, perThread = 200)

        tokens.forEach {
            val decoded = verifier.verify(it)
            assertEquals(applicationId, decoded.getClaim("application_id").asString())
            assertTrue(decoded.issuedAtAsInstant != null)
        }
    }

    @Test
    fun `an explicit id and issued at are kept on every generated token`() {
        val jwt = Jwt.builder().applicationId(applicationId).privateKeyContents(privateKeyContents)
            .id("fixed-id").build()

        val tokens = generateConcurrently(jwt, threads = 8, perThread = 100)

        assertEquals(setOf("fixed-id"), tokens.map { JWT.decode(it).id }.toSet())
    }
}
