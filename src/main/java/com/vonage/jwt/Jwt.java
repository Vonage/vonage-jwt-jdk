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
import com.auth0.jwt.interfaces.DecodedJWT;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public final class Jwt {
	static final String APPLICATION_ID_CLAIM = "application_id";

	private final String privateKeyContents;
	private final JWTCreator.Builder jwtBuilder;
	private final Algorithm algorithm;
	private final DecodedJWT jwt;

	private Jwt(Builder builder) {
		privateKeyContents = builder.privateKeyContents;
		// Hack to avoid having to duplicate the builder's properties in this object.
		jwt = JWT.decode((jwtBuilder = builder.auth0JwtBuilder).sign(Algorithm.none()));
		try {
			algorithm = privateKeyContents == null || privateKeyContents.trim().isEmpty() ?
					Algorithm.none() : Algorithm.RSA256(new KeyConverter().privateKey(privateKeyContents));
		}
		catch (InvalidKeySpecException ex) {
			throw new IllegalStateException(ex);
		}
	}

	public String generate() {
		return jwtBuilder.withJWTId(getId()).withIssuedAt(getIssuedAt()).sign(algorithm);
	}

	public UUID getApplicationId() {
		return UUID.fromString(jwt.getClaim(APPLICATION_ID_CLAIM).asString());
	}

	public String getPrivateKeyContents() {
		return privateKeyContents;
	}

	public Map<String, ?> getClaims() {
		return jwt.getClaims().entrySet().stream().collect(Collectors.toMap(
				Map.Entry::getKey,
				e -> e.getValue().as(Object.class)
		));
	}

	public String getId() {
		String jti = jwt.getId();
		return jti != null ? jti : UUID.randomUUID().toString();
	}

	public Instant getIssuedAt() {
		Instant iat = jwt.getIssuedAtAsInstant();
		return iat != null ? iat : Instant.now();
	}

	public Instant getNotBefore() {
		return jwt.getNotBeforeAsInstant();
	}

	public Instant getExpiresAt() {
		return jwt.getExpiresAtAsInstant();
	}

	public String getSubject() {
		return jwt.getSubject();
	}

	public static class Builder {
		private final JWTCreator.Builder auth0JwtBuilder = JWT.create();
		private UUID applicationId;
		private String privateKeyContents = "";
		private boolean signed = true;

		public Builder applicationId(UUID applicationId) {
			this.applicationId = Objects.requireNonNull(applicationId);
			return withProperties(b -> b.withClaim(APPLICATION_ID_CLAIM, applicationId.toString()));
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

		public Builder withProperties(Consumer<JWTCreator.Builder> jwtBuilder) {
			jwtBuilder.accept(auth0JwtBuilder);
			return this;
		}

		public Builder claims(Map<String, Object> claims) {
			withProperties(b -> b.withPayload(claims));
			return this;
		}

		public Builder addClaim(String key, Object value) {
			return claims(Collections.singletonMap(key, value));
		}

		public Builder issuedAt(ZonedDateTime iat) {
			return withProperties(b -> b.withIssuedAt(iat.toInstant()));
		}

		public Builder id(String jti) {
			return withProperties(b -> b.withJWTId(jti));
		}

		public Builder notBefore(ZonedDateTime nbf) {
			return withProperties(b -> b.withNotBefore(nbf.toInstant()));
		}

		public Builder expiresAt(ZonedDateTime exp) {
			return withProperties(b -> b.withExpiresAt(exp.toInstant()));
		}

		public Builder subject(String sub) {
			return withProperties(b -> b.withSubject(sub));
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
