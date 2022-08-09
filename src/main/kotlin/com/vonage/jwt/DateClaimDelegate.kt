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
package com.vonage.jwt

import java.time.ZonedDateTime
import kotlin.properties.ReadOnlyProperty
import kotlin.reflect.KProperty

class DateClaimDelegate : ReadOnlyProperty<Jwt, ZonedDateTime> {
    override fun getValue(thisRef: Jwt, property: KProperty<*>) = getClaimOrThrowException(
        when (property.name) {
            "issuedAt" -> "iat"
            "notBefore" -> "nbf"
            "expiresAt" -> "exp"
            else -> property.name
        }, thisRef.claims
    )

    private fun getClaimOrThrowException(key: String, claims: Map<String, Any?>) =
        (claims[key] ?: throwNoSuchElementException(key)) as ZonedDateTime

    private fun throwNoSuchElementException(name: String) {
        throw NoSuchElementException("Claim $name is not set.")
    }
}
