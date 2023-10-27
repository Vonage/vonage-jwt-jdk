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

import org.junit.Assert.*;
import org.junit.Test

private const val HS256_SIGNATURE = "0c15c425fe48dd59dab5fb3eea57d528f405a71d78ae4998deacab4deeb02ca5"
private const val TOKEN_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
private const val TOKEN_PAYLOAD = "eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJTaW5hIiwiaWF0IjoxNjk4MjU4NjY3fQ"
private const val TOKEN_SIGNATURE = "ZVSrJeaES6iaBOwd6vMk93my2gq1uCwDi3c7aCIMqa0"
private const val TOKEN_HEADER_PAYLOAD = "$TOKEN_HEADER.$TOKEN_PAYLOAD"
private const val TOKEN = "$TOKEN_HEADER_PAYLOAD.$TOKEN_SIGNATURE"

class JwtValidatorTest {

    @Test
    fun `when token matches signature result is true`() {
        assertTrue(Jwt.verifySignature(TOKEN, HS256_SIGNATURE))
    }

    @Test
    fun `when presented with a incorrect signature result is false`() {
        assertFalse(Jwt.verifySignature(TOKEN, HS256_SIGNATURE.replace('e', 'f')))
    }

    @Test
    fun `when token has no secret result is false`() {
        val unsignedToken = "$TOKEN_HEADER_PAYLOAD.JYE9nZOm-ouJm75YB79ouwStFowe7jsEqNg1ehmmZmE"
        assertFalse(Jwt.verifySignature(unsignedToken, HS256_SIGNATURE))
    }

    @Test
    fun `when incorrect signature is used result is false`() {
        val badSignature = "decafea1deadbeef0123456789abcdef0123456789abcdef0123456789abcdef"
        assertFalse(Jwt.verifySignature(TOKEN, badSignature))

        // The opposite should be true
        val matchingToken = "$TOKEN_HEADER_PAYLOAD.pZ2YiYpipVpf59vZgUHLYICJwhVISwBhy_q9WokKm2A"
        assertTrue(Jwt.verifySignature(matchingToken, badSignature))
    }

    @Test
    fun `when token signature is different result is false`() {
        val badToken = "$TOKEN_HEADER_PAYLOAD.YNz-ojcIge37-LwXjOY835p64iXKPR_iHzLnn1msR50"
        assertFalse(Jwt.verifySignature(badToken, HS256_SIGNATURE))

        // The opposite should be true
        val matchingSignature = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"
        assertTrue(Jwt.verifySignature(badToken, matchingSignature))
    }
}