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
package com.vonage.jwt;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class KeyConverter {
	private static final String
			PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----",
			PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----",
			PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----",
			PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";

	private final KeyFactory keyFactory;

	public KeyConverter(String algorithm) {
		try {
			this.keyFactory = KeyFactory.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	public KeyConverter() {
		this("RSA");
	}

	public RSAPrivateKey privateKey(String key) throws InvalidKeySpecException {
		return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec(sanitize(key)));
	}

	public RSAPublicKey publicKey(String key) throws InvalidKeySpecException {
		return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec(sanitize(key)));
	}

	private String sanitize(String key) {
		return key.replaceAll(PRIVATE_KEY_HEADER, "")
				.replaceAll(PRIVATE_KEY_FOOTER, "")
				.replaceAll(PUBLIC_KEY_HEADER, "")
				.replaceAll(PUBLIC_KEY_FOOTER, "")
				.replaceAll("\\s+", "");
	}

	private byte[] decode(String key) {
		return Base64.getDecoder().decode(key);
	}

	private PKCS8EncodedKeySpec privateKeySpec(String key) {
		return new PKCS8EncodedKeySpec(decode(key));
	}

	private X509EncodedKeySpec publicKeySpec(String key) {
		return new X509EncodedKeySpec(decode(key));
	}
}
