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

import io.jsonwebtoken.Jwts
import org.junit.Test
import java.io.File
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"
private const val PUBLIC_KEY_PATH = "src/test/resources/public.key"

class JwtGeneratorTest {
    val privateKeyContents = File(PRIVATE_KEY_PATH).readText()
    val publicKeyContents = File(PUBLIC_KEY_PATH).readText()

    @Test
    fun `when a jwt has all custom properties those properties are on the generated token`() {
        val expectedToken =
            "eyJ0eXBlIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhcHBsaWNhdGlvbl9pZCI6ImFwcGxpY2F0aW9uLWlkIiwic3ViIjoic3ViamVjdCIsImV4cCI6NjM2NTA4ODAwLCJuYmYiOjYzNjUwODgwMCwiaWF0Ijo2MzY1MDg4MDAsImp0aSI6ImlkIiwiZm9vIjoiYmFyIn0.TTQqqxtcHeaT9UMU7JIQJILs54U2i-yK-suRJM4xyBxYYTTKCy9emGWIOsiROPOxVahOPzjvGOvNQRilceBaQ2JoYPnrCNn8o0qfctxxRhEOQNHIxOvYfYXjncnLTmY2jiG7q4JVN3_GNr-uIoupKnbXOgcKm-rhDBOu4vlMShVOaThb9HqMMyy0lbfIR6XR4IXiFmOSJ3rQIIqqXzAWWwZmj-_u5-5U2kDc6XR4UWW711zrrR3puvAhbIdzy8gVmGFDXBro8137dv6RKOw4l8KskYbe5o5oF2fQsf6Fmjp5R5ZVSa9Kt9_D-XxvADGj8fwEEePsZ0-Xey9hFN5V-A"
        val jwt = Jwt.builder()
            .applicationId("application-id")
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
            "eyJ0eXBlIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhcHBsaWNhdGlvbl9pZCI6ImFwcGxpY2F0aW9uLWlkIiwiZXhwIjo2MzY1MDg4MDAsIm5iZiI6NjM2NTA4ODAwLCJpYXQiOjYzNjUwODgwMCwianRpIjoiaWQifQ.JUrsXb791U_MNJqamJO903T892I2oJFiGmm9nAoZyClat_hk2vAsjY4kfmLJ0PPg3J--FQnVyNBmTyZKdkk60Iu2kMdC9Ysswts9Kd_1h8IoGg85exlj1TLhbx-GLPLKrEzwjtsULOAt_2R-FAhWhBX_kYAxCG19negf0jDy-t96JksNsVy-BJYGUZvUXaHriXurovd1EqcBhuPkS6QQPDl-6vROOLf7x_0uJlOSPkCs5zKsEz5E6VHBdWxezNtOtRAO8-Yj-zHUfVBABuDQIvELAUVOxvB-rxOYPXoM56fWUbXbf9zOBAD57DPublqre4USW5uErcoIc0LjmGMtEg"

        val jwt = Jwt.builder()
            .applicationId("application-id")
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
            "eyJ0eXBlIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhcHBsaWNhdGlvbl9pZCI6ImFwcGxpY2F0aW9uLWlkIiwiZXhwIjo2MzY1MjY4MDAsIm5iZiI6NjM2NTI2ODAwLCJpYXQiOjYzNjUyNjgwMCwianRpIjoiaWQifQ.S3buxZvdjg1ycJC8c-8YxlQYbBkTKFyen9KSa0616pOmhSkUB5wpAYPsiLbQsNYJ6RaD-YJ95mXYCsnEnqcsu122a6vT2EncFOWPk72Rxo8kl6Urr8O21v4m-ZPeiCUgpDP3gEkf9Rj2xrXiDQQ6aaab6bHpC3lD9gFBsbEoSkqsneEIuBZHcvZHyRD5C0NRIdpe-K2gTMdxf1uvoZYFldaKkM-S157dvqvBY3DoghMjIUm6OYFpbBo9pIErwCN5-rYPKya3ydV6zEMpAwTJOqr68B4AKp6pCpn_ewVX6lwqt8wDSTeOKC_3s3g9CuNKntUGDy7R_34wZliL5eGqSQ"

        val jwt = Jwt.builder()
            .applicationId("application-id")
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
            .applicationId("application-id")
            .id("id")
            .privateKeyContents(privateKeyContents)

        val jwtDenver = builder.issuedAt(ZonedDateTime.now(ZoneId.of("America/Denver"))).build()
        val jwtTokyo = builder.issuedAt(ZonedDateTime.now(ZoneId.of("Asia/Tokyo"))).build()

        assertEquals(jwtDenver.generate(), jwtTokyo.generate())
    }

    @Test
    fun `when a jwt only has an application id and secret the other required properties are on the generated token`() {
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyContents(privateKeyContents)
            .build()

        val token = jwt.generate()
        val rsaKey = KeyConverter().publicKey(publicKeyContents)

        val claims = Jwts.parser().verifyWith(rsaKey).build().parseSignedClaims(token)
        assertEquals("JWT", claims.header["type"])
        assertEquals("RS256", claims.header["alg"])
        assertEquals("application-id", claims.payload["application_id"])
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