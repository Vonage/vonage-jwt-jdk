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

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;

public class Jwt {
	private final UUID applicationId;
	private final String privateKeyContents;
	private final Map<String, Object> claims;

	private Jwt(UUID applicationId, String privateKeyContents, Map<String, Object> claims) {
		this.applicationId = applicationId;
		this.privateKeyContents = privateKeyContents;
		this.claims = claims;
	}

	public String generate() {
		return generate(new KeyConverter());
	}

	protected String generate(KeyConverter keyConverter) {
		JwtBuilder jwtBuilder = Jwts.builder()
				.header().add("type", "JWT").and()
				.claims().add("application_id", applicationId)
				.add(fixClaims()).and();

		if (privateKeyContents != null && !privateKeyContents.trim().isEmpty()) try {
			RSAPrivateKey privateKey = keyConverter.privateKey(privateKeyContents);
			jwtBuilder = jwtBuilder.signWith(privateKey, Jwts.SIG.RS256);
		}
		catch (InvalidKeySpecException ex) {
			throw new IllegalStateException(ex);
		}
		return jwtBuilder.compact();
	}

	public UUID getApplicationId() {
		return applicationId;
	}

	public String getPrivateKeyContents() {
		return privateKeyContents;
	}

	public Map<String, ?> getClaims() {
		return claims;
	}

	public String getId() {
		return getClaimOrThrowException("jti");
	}

	public ZonedDateTime getIssuedAt() {
		return getClaimOrThrowException("iat");
	}

	public ZonedDateTime getNotBefore() {
		return getClaimOrThrowException("nbf");
	}

	public ZonedDateTime getExpiresAt() {
		return getClaimOrThrowException("exp");
	}

	public String getSubject() {
		return getClaimOrThrowException("sub");
	}

	@SuppressWarnings("unchecked")
	private <T> T getClaimOrThrowException(String key) {
		if (!claims.containsKey(key)) {
			throw new NoSuchElementException("Claim " + key + " is not set.");
		}
		return (T) claims.get(key);
	}

	private Map<String, Object> fixClaims() {
		Map<String, Object> normalClaims = new LinkedHashMap<>(claims);
		List<String> timeKeys = Arrays.asList("iat", "exp", "nbf");
		Map<String, Object> convertedClaims = new LinkedHashMap<>();
		for (Map.Entry<String, Object> entry : claims.entrySet()) {
			if (timeKeys.contains(entry.getKey()) && entry.getValue() instanceof ZonedDateTime) {
				convertedClaims.put(entry.getKey(), ((ZonedDateTime) entry.getValue()).toEpochSecond());
			}
		}
		normalClaims.putAll(convertedClaims);
		normalClaims.putIfAbsent("iat", Instant.now().getEpochSecond());
		normalClaims.putIfAbsent("jti", UUID.randomUUID().toString());
		return normalClaims;
	}

	public static class Builder {
		private UUID applicationId;
		private String privateKeyContents = "";
		private boolean signed = true;
		private final Map<String, Object> claims = new LinkedHashMap<>();

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
			this.claims.putAll(claims);
			return this;
		}

		public Builder addClaim(String key, Object value) {
			this.claims.put(key, value);
			return this;
		}

		public Builder issuedAt(ZonedDateTime iat) {
			return addClaim("iat", iat);
		}

		public Builder id(String jti) {
			return addClaim("jti", jti);
		}

		public Builder notBefore(ZonedDateTime nbf) {
			return addClaim("nbf", nbf);
		}

		public Builder expiresAt(ZonedDateTime exp) {
			return addClaim("exp", exp);
		}

		public Builder subject(String subject) {
			return addClaim("sub", subject);
		}

		public Jwt build() {
			validate();
			return new Jwt(applicationId, privateKeyContents, claims);
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
			SecretKeySpec secretSpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
			Jwts.parser().verifyWith(secretSpec).build().parse(token);
			return true;
		} catch (SignatureException ex) {
			return false;
		}
	}
}
