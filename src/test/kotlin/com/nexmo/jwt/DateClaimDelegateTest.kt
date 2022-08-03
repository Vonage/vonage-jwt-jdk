/*
 * Copyright 2022 Vonage
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

import org.junit.Test
import org.mockito.BDDMockito.given
import org.mockito.Mockito
import java.nio.file.Paths
import java.time.ZonedDateTime
import kotlin.reflect.KProperty
import kotlin.test.assertEquals

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"

class DateClaimDelegateTest {
    @Test
    fun `when issuedAt property is requested the iat value is read from the claim map`() {
        val now = ZonedDateTime.now()
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("iat" to now))
            .build()

        assertEquals(now, jwt.issuedAt)
    }

    @Test
    fun `when expiresAt property is requested the exp value is read from the claim map`() {
        val now = ZonedDateTime.now()
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("exp" to now))
            .build()

        assertEquals(now, jwt.expiresAt)
    }

    @Test
    fun `when notBefore property is requested the nbf value is read from the claim map`() {
        val now = ZonedDateTime.now()
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("nbf" to now))
            .build()

        assertEquals(now, jwt.notBefore)
    }

    @Test(expected = NoSuchElementException::class)
    fun `when the property does not exist on the map a NoSuchElementException is thrown`() {
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .build()

        jwt.expiresAt // Throws exception
    }

    @Test(expected = NoSuchElementException::class)
    fun `when delegate gets a property that cant be translated a NoSuchElementException is thrown`() {
        val jwt = Jwt.builder().applicationId("application-id").privateKeyPath(Paths.get(PRIVATE_KEY_PATH)).build()

        val mockProperty = Mockito.mock(KProperty::class.java)
        given(mockProperty.name).willReturn("fooBar")

        DateClaimDelegate().getValue(jwt, mockProperty) // Throws exception
    }
}