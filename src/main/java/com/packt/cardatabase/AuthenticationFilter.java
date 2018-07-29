package com.packt.cardatabase;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.packt.cardatabase.service.AuthenticationService;

//GenericFilterBean is a generic superclass used for any kind of filter
//This class handles authentication for any endpoint EXCEPT /login
public class AuthenticationFilter extends GenericFilterBean {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
	  
	  //Get the JWT from the request Authorization header using our AuthenticationService
	  Authentication authentication = AuthenticationService.getAuthentication((HttpServletRequest)request);
    
	  //Put the Authentication object in our SecurityContextHolder (which associates a given SecurityContext with the current execution thread)
	  SecurityContextHolder.getContext().setAuthentication(authentication);
	  filterChain.doFilter(request, response);		//see java.servlet.filter
  }
}