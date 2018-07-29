package com.packt.cardatabase.service;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import static java.util.Collections.emptyList;


public class AuthenticationService {
	
	static final long EXPIRATIONTIME = 604_800_000;	//1 week in milliseconds
	static final String SIGNINGKEY = "SecretKey";
	static final String PREFIX = "Bearer";
	
	//Add token to Authorization header
	static public void addToken(HttpServletResponse res, String username) {
		
		//Create JWT with username, expiration date, and signing algorithm
		String Jwt = Jwts.builder().setSubject(username).setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
				.signWith(SignatureAlgorithm.HS512, SIGNINGKEY).compact();
		
		//Add JWT to Authorization header in format client should expect
		res.addHeader("Authorization", PREFIX + " " +  Jwt);
		
	}
	
	//Get token from Authorization header (or authentication)
	public static Authentication getAuthentication(HttpServletRequest request) {
		
		String token = request.getHeader("Authorization");
		
		if (token != null) {
			String user = Jwts.parser().setSigningKey(SIGNINGKEY).parseClaimsJws(token.replace(PREFIX, ""))		//this is replace(oldChar, newChar)
					.getBody().getSubject();
			
			if (user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, emptyList());
			}
		}
		
		return null;
	}
	
}
