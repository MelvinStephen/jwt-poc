package com.yantriks.jwt;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JwtCreator {

	private static String issuer = "ISSUER";

	private static String privateKey = "PRIVATE-KEY";

	private static String privateKeyId = "PRIVATE-KEY-ID";

	private static String audience = "AUDIENCE";

	//In minutes 
	private static int validity = 1;

	public static void main(String[] args) throws Exception {

		RSAPrivateKey key = (RSAPrivateKey) getPrivateKey(privateKey);

		Algorithm algorithm = Algorithm.RSA256(null, key);
		String token = JWT.create()
				.withKeyId(privateKeyId)
				.withIssuer(issuer)
				.withSubject(issuer)
				.withAudience(audience)
				.withIssuedAt(asDate(LocalDateTime.now()))
				.withExpiresAt(asDate(LocalDateTime.now().plusMinutes(validity)))
				.sign(algorithm);

		System.out.println("Generated JWT");
		System.out.println("--------------------------------------------------------------------------------------------------------------------------------");
		System.out.println(token);
		System.out.println("--------------------------------------------------------------------------------------------------------------------------------");
	}
	
	private static Date asDate(LocalDateTime dateTime) {
		return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
	}

	private static PrivateKey getPrivateKey(String privateKey) throws Exception {
		// Read in the key into a String
		StringBuilder pkcs8Lines = new StringBuilder();
		BufferedReader rdr = new BufferedReader(new StringReader(privateKey));
		String line;
		while ((line = rdr.readLine()) != null) {
			pkcs8Lines.append(line);
		}

		// Remove the "BEGIN" and "END" lines, as well as any whitespace
		String pkcs8Pem = pkcs8Lines.toString();
		pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
		pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
		pkcs8Pem = pkcs8Pem.replaceAll("\\\\n", "");

		// Base64 decode the result
		byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);

		// extract the private key
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(keySpec);

	}
}
