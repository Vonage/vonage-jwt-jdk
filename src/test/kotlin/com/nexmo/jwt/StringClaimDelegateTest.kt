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
import kotlin.reflect.KProperty
import kotlin.test.assertEquals

private const val PRIVATE_KEY_PATH = "src/test/resources/private.key"

class StringClaimDelegateTest {
    @Test
    fun `when subject property is requested the sub value is read from the claim map`() {
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("sub" to "subject"))
            .build()

        assertEquals("subject", jwt.subject)
    }

    @Test
    fun `when id property is requested the jti value is read from the claim map`() {
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .claims(mapOf("jti" to "id"))
            .build()

        assertEquals("id", jwt.id)
    }

    @Test(expected = NoSuchElementException::class)
    fun `when the property does not exist on the map a NoSuchElementException is thrown`() {
        val jwt = Jwt.builder()
            .applicationId("application-id")
            .privateKeyPath(Paths.get(PRIVATE_KEY_PATH))
            .build()

        jwt.id // Throws exception
    }

    @Test(expected = NoSuchElementException::class)
    fun `when delegate gets a property that cant be translated a NoSuchElementException is thrown`() {
        val jwt = Jwt.builder().applicationId("application-id").privateKeyPath(Paths.get(PRIVATE_KEY_PATH)).build()

        val mockProperty = Mockito.mock(KProperty::class.java)
        given(mockProperty.name).willReturn("fooBar")

        StringClaimDelegate().getValue(jwt, mockProperty) // Throws exception
    }
}