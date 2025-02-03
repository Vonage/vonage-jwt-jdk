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
import com.auth0.jwt.interfaces.DecodedJWT
import org.junit.Test
import java.io.File
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"
private const val PUBLIC_KEY_PATH = "src/test/resources/public.key"

class JwtGeneratorTest {
    private val applicationId = "00000000-0000-4000-8000-000000000000"
    private val privateKeyContents = File(PRIVATE_KEY_PATH).readText()
    private val publicKeyContents = File(PUBLIC_KEY_PATH).readText()
    private val expectedHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    private val rsaKey = KeyConverter().publicKey(publicKeyContents)

    @Test
    fun `when a jwt has all custom properties those properties are on the generated token`() {
        val expectedToken =
            "$expectedHeader.eyJhcHBsaWNhdGlvbl9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCIsInN1YiI6InN1YmplY3QiLCJleHAiOjYzNjUwODgwMCwibmJmIjo2MzY1MDg4MDAsImlhdCI6NjM2NTA4ODAwLCJqdGkiOiJpZCIsImZvbyI6ImJhciJ9.CCq0rpkBtw-vgcAv1OB46044g60MtHK-839jn4xuEby8NjmwU1X1N1YH8IKKt-Cng-Eh23Qcm9sgWF-9M0fNCvUuFK6sGN2_HXk84abQIigudiGIwbv9OkQZpu4F-fuiq78jC2o8Z8KaZwZuR5Ni9vBObfu_3WHIO_jUnEsDss0RBNqyc9CDpTn9R6G6yxZeqmC1vFfCzfsmP4QO6u7CiT8GQTbvcusS11LNqeXnJcxY7c-BVsfhtj4P-FeB2cX2Bpm5duX92QkNmeywq9yjkF5T8R5x64V_0L6VF1clFhWTfyzaSG4m62o0T9wNYG7mdXJYU_LY64Q4vwPmer8j1g"

        val token = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .subject("subject")
            .expiresAt(testDateInUtc())
            .notBefore(testDateInUtc())
            .issuedAt(testDateInUtc())
            .id("id")
            .addClaim("foo", "bar")
            .build().generate()

        assertEquals(expectedToken, token)
    }

    @Test
    fun `when a jwt is given a time in utc then the expiration, not before, issued at, and custom claim are in utc`() {
        val expectedToken =
            "$expectedHeader.eyJhcHBsaWNhdGlvbl9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCIsImV4cCI6NjM2NTA4ODAwLCJuYmYiOjYzNjUwODgwMCwiaWF0Ijo2MzY1MDg4MDAsImp0aSI6ImlkIn0.d7pZqR2ZNiZJranOMVsHsE98H28QguRy9q_kbKDFVDbYQfJaqDbyyvnvCP9p4AUvIWbUsNF-XOsFwxLSvQaYVDvL0GvQHIURFKRyhkDiL7iZhj0EGWsTWJSahBIDZfZ5ieX0A6FowdVKiYCQ4zlmpmFM21zSD_E9Lsjgk0QiRCT9dHnwxs_ARA5fOCFBG16SrQ25P4gLICRviPSaLJHDWOTLCBeeuwcOnPH2SlUkJ__PNKhNnnxyLbRqZ6CwyUlxWlc5UzCPwuxZ9wJHVsH1hn_Zrv8XVJBjSL205pFPB-QNZN007e-6MCRxqEah_dINTn1a-aYPM4YeEAQaYMO6tw"

        val token = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .expiresAt(testDateInUtc())
            .notBefore(testDateInUtc())
            .issuedAt(testDateInUtc())
            .id("id")
            .build().generate()

        assertEquals(expectedToken, token)
    }

    @Test
    fun `when a jwt is given a time in est then the expiration, not before, issued at, and custom claim are in utc`() {
        val expectedToken =
            "$expectedHeader.eyJhcHBsaWNhdGlvbl9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCIsImV4cCI6NjM2NTI2ODAwLCJuYmYiOjYzNjUyNjgwMCwiaWF0Ijo2MzY1MjY4MDAsImp0aSI6ImlkIn0.SoPnY7Vl1L0iqZTJ40DRHU1YTZy90kPe59-QwW_syR2klT6IOr0lhTf5oKX9jY6Ha8dFt5HHTTJ8egofT39myqEC-l2ICMwM0Yr5G2NXCj2kdx2O5OL-wjAk0rZGivdXyrBnf4S-qp8-ch-WfwJ94tQfZU3-2laOUIC8xBEuW-EuuqvsFiVUWHpyCpnPefVxe2ppNoIXOqJhkYvAv5vhgZwaxS21akBeWGIRZoDINz5v0toFnzEjrCQ0KWqZjDfeu9PXL67-qkHTJdWIJTknp7XMjEKX4cyUUhto-lAWXLM2hHg-_bgK3fjlAPTq8HyRBB6d2Y9cqOpN1bKwz3Xk0w"

        val token = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .expiresAt(testDateInEst())
            .notBefore(testDateInEst())
            .issuedAt(testDateInEst())
            .id("id")
            .build().generate()

        assertEquals(expectedToken, token)
    }

    @Test
    fun `when two jwts are generated for the same issued time, but different time zones, the tokens are the same`() {
        val builder = Jwt.builder()
            .applicationId(applicationId)
            .id("id")
            .privateKeyContents(privateKeyContents)

        val jwtDenver = builder.issuedAt(ZonedDateTime.now(ZoneId.of("America/Denver"))).build()
        val jwtTokyo = builder.issuedAt(ZonedDateTime.now(ZoneId.of("Asia/Tokyo"))).build()

        assertEquals(jwtDenver.generate(), jwtTokyo.generate())
    }

    @Test
    fun `when a jwt only has an application id and secret the other required properties are on the generated token`() {
        val token = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .build().generate()

        val decoded = decodeJwt(token)
        assertEquals(expectedHeader, decoded.header)
        assertEquals(applicationId, decoded.claims["application_id"]?.asString())
        assertTrue(decoded.claims.containsKey("iat"))
        assertTrue(decoded.claims.containsKey("jti"))
        assertNotNull(decoded.signature)
    }

    @Test
    fun `when id is empty the jwt is generated with a random UUID for jti claim`() {
        val token = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .id(" \t\n  ").build().generate()

        val decoded = decodeJwt(token)
        val jti = decoded.claims["jti"]?.asString()
        assertNotNull(jti)
        assertEquals(jti, UUID.fromString(jti).toString())
    }

    @Test
    fun `when privateKeyContents is empty the jwt is unsigned`() {
        val token = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents("   ")
            .build().generate()

        val decoded = decodeUnsignedJwt(token)
        assertEquals(0, decoded.signature.length)
        assertEquals(Algorithm.none().name, decoded.algorithm)
    }

    @Test
    fun `when a map is given as claim value then it is jsonified in generated string`() {
        val token : String = Jwt.builder()
            .applicationId("aaaaaaaa-bbbb-cccc-dddd-0123456789ab")
            .privateKeyContents(privateKeyContents)
            .issuedAt(ZonedDateTime.now())
            .id("705b6f50-8c21-11e8-9bcb-595326422d60")
            .subject("alice")
            .expiresAt(ZonedDateTime.now().plusMinutes(20))
            .addClaim("acl", mapOf(
                "paths" to mapOf(
                    "/*/users/**" to mapOf<String, Any>(),
                    "/*/conversations/**" to mapOf(),
                    "/*/sessions/**" to mapOf(),
                    "/*/devices/**" to mapOf(),
                    "/*/image/**" to mapOf(),
                    "/*/media/**" to mapOf(),
                    "/*/applications/**" to mapOf(),
                    "/*/push/**" to mapOf(),
                    "/*/knocking/**" to mapOf(),
                    "/*/legs/**" to mapOf()
                )
            )).build().generate()

        val decoded = decodeJwt(token)
        val acl = decoded.claims["acl"]?.asMap()
        assertNotNull(acl)
        val paths = acl["paths"] as Map<*, *>
        assertEquals(10, paths.entries.size)
    }

    private fun decodeJwt(token: String): DecodedJWT = JWT.require(Algorithm.RSA256(rsaKey)).build().verify(token)
    private fun decodeUnsignedJwt(token: String): DecodedJWT = JWT.decode(token)
    private fun testDateInUtc() = ZonedDateTime.of(LocalDateTime.of(1990, 3, 4, 0, 0, 0), ZoneId.of("UTC"))
    private fun testDateInEst() = ZonedDateTime.of(LocalDateTime.of(1990, 3, 4, 0, 0, 0), ZoneId.of("America/Detroit"))
}