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
package com.vonage.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Class which allows declaratively specifying claims for generating Json Web Tokens (JWTs).
 * The {@link #builder()} static method provides the entry point, from which the mandatory
 * and optional parameters can be specified. After calling {@linkplain Builder#build()}, the
 * options can be re-used to create new tokens using the {@link #generate()} method.
 * <p>
 * Signed JWTs can be verified using the static {@link #verifySignature(String, String)} method.
 */
public final class Jwt {
	static final String APPLICATION_ID_CLAIM = "application_id";

	private final JWTCreator.Builder jwtBuilder;
	private final Algorithm algorithm;
	private final DecodedJWT jwt;

	private Jwt(Builder builder) {
		// Hack to avoid having to duplicate the builder's properties in this object.
		jwt = JWT.decode((jwtBuilder = builder.auth0JwtBuilder).sign(Algorithm.none()));
		try {
			algorithm = builder.signed ?
					Algorithm.RSA256(new KeyConverter().privateKey(builder.privateKeyContents)) :
					Algorithm.none();
		}
		catch (InvalidKeySpecException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/**
	 * Creates a new Base64-encoded JWT using the settings specified in the builder.
	 *
	 * @return A new Json Web Token as a string.
	 */
	public String generate() {
		String jti = getId();
		if (jti == null || jti.trim().isEmpty()) {
			jwtBuilder.withJWTId(UUID.randomUUID().toString());
		}

		Instant iat = getIssuedAt();
		if (iat == null) {
			jwtBuilder.withIssuedAt(Instant.now());
		}

		return jwtBuilder.sign(algorithm);
	}

	/**
	 * Returns the {@code application_id} claim.
	 *
	 * @return The Vonage application UUID.
	 */
	public UUID getApplicationId() {
		return UUID.fromString(jwt.getClaim(APPLICATION_ID_CLAIM).asString());
	}

	/**
	 * Returns all claims, both standard and non-standard.
	 *
	 * @return The claims on this JWT as a Map.
	 */
	public Map<String, ?> getClaims() {
		return jwt.getClaims().entrySet().stream().collect(Collectors.toMap(
				Map.Entry::getKey,
				e -> e.getValue().as(Object.class)
		));
	}

	/**
	 * Returns the {@code jti} claim.
	 *
	 * @return The JWT ID as a string, or {@code null} if unspecified.
	 */
	public String getId() {
		return jwt.getId();
	}

	/**
	 * Returns the {@code iat} claim.
	 *
	 * @return The issue time as an Instant, or {@code null} if unspecified.
	 */
	public Instant getIssuedAt() {
		return jwt.getIssuedAtAsInstant();
	}

	/**
	 * Returns the {@code nbf} claim.
	 *
	 * @return The start (not before) time as an Instant, or {@code null} if unspecified.
	 */
	public Instant getNotBefore() {
		return jwt.getNotBeforeAsInstant();
	}

	/**
	 * Returns the {@code exp} claim.
	 *
	 * @return The expiry time as an Instant, or {@code null} if unspecified.
	 */
	public Instant getExpiresAt() {
		return jwt.getExpiresAtAsInstant();
	}

	/**
	 * Returns the {@code sub} claim.
	 *
	 * @return The subject, or {@code null} if unspecified.
	 */
	public String getSubject() {
		return jwt.getSubject();
	}

	/**
	 * Builder for setting the properties of a JWT.
	 */
	public static class Builder {
		private final JWTCreator.Builder auth0JwtBuilder = JWT.create();
		String privateKeyContents = "";
		UUID applicationId;
		boolean signed = true;

		/**
		 * (REQUIRED)
		 * Sets the application ID. This must be your Vonage application ID.
		 *
		 * @param applicationId The application UUID.
		 * @return This builder.
		 */
		public Builder applicationId(UUID applicationId) {
			this.applicationId = Objects.requireNonNull(applicationId);
			return withProperties(b -> b.withClaim(APPLICATION_ID_CLAIM, applicationId.toString()));
		}

		/**
		 * (REQUIRED)
		 * Sets the application ID. This must be your Vonage application ID.
		 *
		 * @param applicationId The application ID as a string. Note that this must be a valid UUID.
		 * @return This builder.
		 */
		public Builder applicationId(String applicationId) {
			return applicationId(UUID.fromString(applicationId));
		}

		/**
		 * (CONDITIONAL)
		 * Create an unsigned token. Calling this means you won't need to provide a private key.
		 *
		 * @return This builder.
		 */
		public Builder unsigned() {
			this.signed = false;
			return this;
		}

		/**
		 * (CONDITIONAL)
		 * Sets the private key used for signing the JWT.
		 *
		 * @param privateKeyContents The actual private key as a string.
		 * @return This builder.
		 */
		public Builder privateKeyContents(String privateKeyContents) {
			this.privateKeyContents = Objects.requireNonNull(privateKeyContents);
			this.signed = !privateKeyContents.isEmpty();
			return this;
		}

		/**
		 * (CONDITIONAL)
		 * Sets the private key by reading it from a file.
		 *
		 * @param privateKeyPath Absolute path to the private key file.
		 * @return This builder.
		 *
		 * @throws IOException If the private key couldn't be read from the file.
		 */
		public Builder privateKeyPath(Path privateKeyPath) throws IOException {
			return privateKeyContents(new String(Files.readAllBytes(privateKeyPath)));
		}

		/**
		 * (CONDITIONAL)
		 * Sets the private key by reading it from a file. This is a convenience
		 * method which simply delegates to {@linkplain #privateKeyPath(Path)}.
		 *
		 * @param privateKeyPath Absolute path to the private key file.
		 * @return This builder.
		 *
		 * @throws IOException If the private key couldn't be read from the file.
		 */
		public Builder privateKeyPath(String privateKeyPath) throws IOException {
			return privateKeyPath(Paths.get(privateKeyPath));
		}

		/**
		 * (OPTIONAL)
		 * This method enables specifying claims and other properties using the Auth0 JWT builder.
		 *
		 * @param jwtBuilder Lambda expression which sets desired properties on the builder.
		 * @return This builder.
		 */
		public Builder withProperties(Consumer<JWTCreator.Builder> jwtBuilder) {
			jwtBuilder.accept(auth0JwtBuilder);
			return this;
		}

		/**
		 * (OPTIONAL)
		 * Sets additional custom claims of the generated JWTs.
		 *
		 * @param claims The claims to add as a Map.
		 * @return This builder.
		 *
		 * @see #addClaim(String, Object)
		 * @see #withProperties(Consumer)
		 */
		public Builder claims(Map<String, ?> claims) {
			withProperties(b -> b.withPayload(claims));
			return this;
		}

		/**
		 * (OPTIONAL)
		 * Adds a custom claim for generated JWTs.
		 *
		 * @param key Name of the claim.
		 * @param value Serializable value of the claim.
		 *
		 * @return This builder.
		 *
		 * @see #claims(Map)
		 * @see #withProperties(Consumer)
		 */
		public Builder addClaim(String key, Object value) {
			return claims(Collections.singletonMap(key, value));
		}

		/**
		 * (OPTIONAL)
		 * Sets the {@code iat} claim.
		 * If unspecified, the current time will be used every time a new JWT is generated.
		 *
		 * @param iat The issue time of generated JWTs.
		 * @return This builder.
		 */
		public Builder issuedAt(ZonedDateTime iat) {
			return withProperties(b -> b.withIssuedAt(iat.toInstant()));
		}

		/**
		 * (OPTIONAL)
		 * Sets the {@code jti} claim.
		 * If unspecified, a random UUID will be used every time a new JWT is generated.
		 *
		 * @param jti The ID (nonce) of the generated JWTs.
		 * @return This builder.
		 */
		public Builder id(String jti) {
			return withProperties(b -> b.withJWTId(jti));
		}

		/**
		 * (OPTIONAL)
		 * Sets the {@code nbf} claim.
		 *
		 * @param nbf The start time at which the generated JWTs will be valid from.
		 * @return This builder.
		 */
		public Builder notBefore(ZonedDateTime nbf) {
			return withProperties(b -> b.withNotBefore(nbf.toInstant()));
		}

		/**
		 * (OPTIONAL)
		 * Sets the {@code exp} claim.
		 *
		 * @param exp The expiry time of generated JWTs.
		 * @return This builder.
		 */
		public Builder expiresAt(ZonedDateTime exp) {
			return withProperties(b -> b.withExpiresAt(exp.toInstant()));
		}

		/**
		 * (OPTIONAL)
		 * Sets the {@code sub} claim.
		 *
		 * @param sub The subject of generated JWTs.
		 * @return This builder.
		 */
		public Builder subject(String sub) {
			return withProperties(b -> b.withSubject(sub));
		}

		/**
		 * Builds the JWT generator using this builder's settings.
		 *
		 * @return A new JWT generator instance.
		 * @throws IllegalStateException If the required properties were not set.
		 */
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
			Objects.requireNonNull(token, "Token cannot be null.");
			Objects.requireNonNull(secret, "Secret cannot be null.");
			JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
			return true;
		}
		catch (JWTVerificationException ex) {
			return false;
		}
	}
}
