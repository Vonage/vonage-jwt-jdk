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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;

public class Jwt {
	private final UUID applicationId;
	private final String privateKeyContents;
	private final ZonedDateTime issuedAt, expiresAt, notBefore;
	private final String jwtId, subject;
	private final Map<String, Object> customClaims;

	private Jwt(Builder builder) {
		applicationId = builder.applicationId;
		privateKeyContents = builder.privateKeyContents;
		subject = builder.subject;
		jwtId = builder.jwtId;
		issuedAt = builder.issuedAt;
		expiresAt = builder.expiresAt;
		notBefore = builder.notBefore;
		customClaims = builder.customClaims;
	}

	public String generate() {
		return generate(new KeyConverter());
	}

	protected String generate(KeyConverter keyConverter) {
		JWTCreator.Builder jwtBuilder = JWT.create()
				.withClaim("application_id", applicationId.toString())
				.withIssuedAt(getIssuedAt() != null ? getIssuedAt().toInstant() : Instant.now())
				.withNotBefore(getNotBefore().toInstant())
				.withExpiresAt(getExpiresAt().toInstant())
				.withJWTId(getId() != null ? getId() : UUID.randomUUID().toString())
				.withHeader(Collections.singletonMap("type", "JWT"));

		try {
			Method addClaimMethod = JWTCreator.Builder.class.getDeclaredMethod("addClaim", String.class, Object.class);
			for (Map.Entry<String, ?> entry : customClaims.entrySet()) {
				addClaimMethod.invoke(jwtBuilder, entry.getKey(), entry.getValue());
			}
		}
		catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ex) {
			throw new IllegalStateException(ex);
		}

		Algorithm algorithm;
		try {
			algorithm = Algorithm.RSA256(keyConverter.privateKey(privateKeyContents));
		}
		catch (InvalidKeySpecException ex) {
			throw new IllegalStateException(ex);
		}

		return jwtBuilder.sign(algorithm);
	}

	public UUID getApplicationId() {
		return applicationId;
	}

	public String getPrivateKeyContents() {
		return privateKeyContents;
	}

	public Map<String, ?> getCustomClaims() {
		return customClaims;
	}

	public String getId() {
		return jwtId;
	}

	public ZonedDateTime getIssuedAt() {
		return issuedAt;
	}

	public ZonedDateTime getNotBefore() {
		return notBefore;
	}

	public ZonedDateTime getExpiresAt() {
		return expiresAt;
	}

	public String getSubject() {
		return subject;
	}

	public static class Builder {
		private final Map<String, Object> customClaims = new LinkedHashMap<>();
		private UUID applicationId;
		private String privateKeyContents = "", jwtId, subject;
		private boolean signed = true;
		private ZonedDateTime issuedAt, expiresAt, notBefore;

		public Builder applicationId(UUID applicationId) {
			this.applicationId = Objects.requireNonNull(applicationId);
			return this;
		}

		public Builder applicationId(String applicationId) {
			return applicationId(UUID.fromString(applicationId));
		}

		public Builder unsigned() {
			this.signed = false;
			return this;
		}

		public Builder privateKeyContents(String privateKeyContents) {
			this.privateKeyContents = Objects.requireNonNull(privateKeyContents);
			this.signed = !privateKeyContents.isEmpty();
			return this;
		}

		public Builder privateKeyPath(Path privateKeyPath) throws Exception {
			return privateKeyContents(new String(Files.readAllBytes(privateKeyPath)));
		}

		public Builder privateKeyPath(String privateKeyPath) throws Exception {
			return privateKeyPath(Paths.get(privateKeyPath));
		}

		public Builder claims(Map<String, Object> claims) {
			this.customClaims.putAll(claims);
			return this;
		}

		public Builder addClaim(String key, Object value) {
			this.customClaims.put(key, value);
			return this;
		}

		public Builder issuedAt(ZonedDateTime iat) {
			this.issuedAt = iat;
			return this;
		}

		public Builder id(String jti) {
			this.jwtId = jti;
			return this;
		}

		public Builder notBefore(ZonedDateTime nbf) {
			this.notBefore = nbf;
			return this;
		}

		public Builder expiresAt(ZonedDateTime exp) {
			this.expiresAt = exp;
			return this;
		}

		public Builder subject(String subject) {
			this.subject = subject;
			return this;
		}

		public Jwt build() {
			validate();
			return new Jwt(this);
		}

		private void validate() {
			if (applicationId == null && privateKeyContents.isEmpty()) {
				throw new IllegalStateException("Both an Application ID and Private Key are required.");
			}
			if (applicationId == null) {
				throw new IllegalStateException("Application ID is required.");
			}
			if (privateKeyContents.trim().isEmpty() && signed) {
				throw new IllegalStateException("Private Key is required for signed token.");
			}
		}
	}

	/**
	 * Instantiate a new Builder for building Jwt objects.
	 *
	 * @return A new Builder.
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Determines whether the provided JSON Web Token was signed by a given SHA-256 HMAC secret.
	 *
	 * @param secret The 256-bit symmetric HMAC signature.
	 * @param token The encoded JWT to check.
	 *
	 * @return {@code true} iff the token was signed by the secret, {@code false} otherwise.
	 *
	 * @since 1.1.0
	 */
	public static boolean verifySignature(String token, String secret) {
		try {
			JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
			return true;
		}
		catch (JWTVerificationException ex) {
			return false;
		}
	}
}
