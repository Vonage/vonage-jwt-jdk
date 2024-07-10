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
import org.junit.Test
import java.io.File
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"
private const val PUBLIC_KEY_PATH = "src/test/resources/public.key"

class JwtGeneratorTest {
    private val applicationId = "00000000-0000-4000-8000-000000000000"
    private val privateKeyContents = File(PRIVATE_KEY_PATH).readText()
    private val publicKeyContents = File(PUBLIC_KEY_PATH).readText()

    @Test
    fun `when a jwt has all custom properties those properties are on the generated token`() {
        val expectedToken =
            "eyJ0eXBlIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhcHBsaWNhdGlvbl9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCIsInN1YiI6InN1YmplY3QiLCJleHAiOjYzNjUwODgwMCwibmJmIjo2MzY1MDg4MDAsImlhdCI6NjM2NTA4ODAwLCJqdGkiOiJpZCIsImZvbyI6ImJhciJ9.UfQRKa0_KMOGPikRrt5iOgIMx1_nIYJI7bVgazMZpJQCe0-XaqBQPgnRicbHfZcoptq0v-mHbcuMUE3OjUqyUlv6WHwVSGAJg4QH_4rRRvK9aD7Puc6Wvq8AYE41TJkPbkdpCIRMVEuMJmZqCT3M5Sh33pbPbMZG0VQrgCQkMvHReeiequ9XlpFqFg7_E5_3G4PHsr6XQDHpfwXDmDMnh7f-5yFNzY7Nn4WAB6EMtlrxM6Ic-cFTSMGAauZZxcAV2ydXKX7ainDJ3VlsKVajTbyUaBCztBkmhmSqQJ4kDZYpxH6HlmMqy1Jd2AtP419sXX_1nw6pWSaFJvOm9QN2eQ"

        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .subject("subject")
            .expiresAt(testDateInUtc())
            .notBefore(testDateInUtc())
            .issuedAt(testDateInUtc())
            .id("id")
            .addClaim("foo", "bar")
            .build()

        val token = jwt.generate()
        assertEquals(expectedToken, token)
    }

    @Test
    fun `when a jwt is given a time in utc then the expiration, not before, issued at, and custom claim are in utc`() {
        val expectedToken =
            "eyJ0eXBlIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhcHBsaWNhdGlvbl9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCIsImV4cCI6NjM2NTA4ODAwLCJuYmYiOjYzNjUwODgwMCwiaWF0Ijo2MzY1MDg4MDAsImp0aSI6ImlkIn0.pYAmQ6hikVxScJq8pGmo1qJhPss38jMSXIAbORhko724vVFVpK4oRuyE0wuOZVotXhEc-b-Epw6pXQJ5EZ5WitHI4ZX-8nyYbaFNUfR9TwzK_79kCLvBgIDFK3p3TVm61PZ-9lk4Gtfg2tNIlD11zoBa0OMMKr-9KKWHyIE7KBpUZLG_YoNx8rBAfaPYGrhpHOUAQMYQGT9Nv5aqjwgH-dgi6gI4paRNos2Wxdq4k15Oz-YKrkGx0Rj497ovGc4SWPFcv_SFnXJTk_gVCOj5_cHEnhIEumbuNVCz6UVGj7yhQVgiuIvQcNOAy3sV9EDMZs6e2QPtZ4ea1QhL0o1W1w"

        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .expiresAt(testDateInUtc())
            .notBefore(testDateInUtc())
            .issuedAt(testDateInUtc())
            .id("id")
            .build()

        val token = jwt.generate()
        assertEquals(expectedToken, token)
    }

    @Test
    fun `when a jwt is given a time in est then the expiration, not before, issued at, and custom claim are in utc`() {
        val expectedToken =
            "eyJ0eXBlIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhcHBsaWNhdGlvbl9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCIsImV4cCI6NjM2NTI2ODAwLCJuYmYiOjYzNjUyNjgwMCwiaWF0Ijo2MzY1MjY4MDAsImp0aSI6ImlkIn0.XCstip9EYuCwn2mU10roc8JrOobgw-kawSEf9aC0QkshkouzHFoTe0wrtu3wJk_CuBodpudWWF2fQ3jZ-L4OrGKZUrb7KYU9Melmh7DrjkRIAmlSaNXoGUgJiz65uIgZFVt-fas3D3jYOeSc9OVQHCdrYJ4zgYtBNkKH5jFah-Kj038PX4I_MOpd4iz3X0ghx7aLl2HHS8VzGYZ_UVNrknJ7p7Ccxgq_hKNNqf0mT9zFM7OxqGVyn67-mF4X7ZE-DoD76KUUWUQBCINxTlVdEo2tSzAwFwCAe-6uN04OFstF38NKN96Prip-XSi3lvzrFG2prX4Us0dj0BjBighNmw"

        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .expiresAt(testDateInEst())
            .notBefore(testDateInEst())
            .issuedAt(testDateInEst())
            .id("id")
            .build()

        val token = jwt.generate()
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
        val jwt = Jwt.builder()
            .applicationId(applicationId)
            .privateKeyContents(privateKeyContents)
            .build()

        val token = jwt.generate()
        val rsaKey = KeyConverter().publicKey(publicKeyContents)

        val claims = Jwts.parser().verifyWith(rsaKey).build().parseSignedClaims(token)
        assertEquals("JWT", claims.header["type"])
        assertEquals("RS256", claims.header["alg"])
        assertEquals(applicationId, claims.payload["application_id"])
        assertTrue(claims.payload.containsKey("iat"))
        assertTrue(claims.payload.containsKey("jti"))
        assertTrue(Jwts.parser().build().isSigned(token))
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
            ))
            .build()
            .generate()

        val rsaKey = KeyConverter().publicKey(publicKeyContents)
        val parsedClaims = Jwts.parser().verifyWith(rsaKey).build().parseSignedClaims(token)
        val acl = parsedClaims.payload["acl"]
        val paths = (acl as Map<*, *>)["paths"] as Map<*, *>
        assertEquals(10, paths.entries.size)
    }

    private fun testDateInUtc() = ZonedDateTime.of(LocalDateTime.of(1990, 3, 4, 0, 0, 0), ZoneId.of("UTC"))
    private fun testDateInEst() = ZonedDateTime.of(LocalDateTime.of(1990, 3, 4, 0, 0, 0), ZoneId.of("America/Detroit"))
}