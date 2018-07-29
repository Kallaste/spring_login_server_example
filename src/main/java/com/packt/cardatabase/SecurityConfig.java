package com.packt.cardatabase;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.packt.cardatabase.service.UserDetailServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private UserDetailServiceImpl userDetailsService; 

	
	  @Override
	  protected void configure(HttpSecurity http) throws Exception {
		  
		  //Disable authentication and cors for POST requests to the /login endpoint
		  http.csrf().disable().cors().and().authorizeRequests().antMatchers(HttpMethod.POST, "/login").permitAll()
	      
		  //For other endpoints, any request must be authenticated or else we should return a 401 response
		  .anyRequest().authenticated().and()
	        
	      // Filter for the /login requests: send these to our LoginFilter
	      .addFilterBefore(new LoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
	        
	      // Filter for other requests to check JWT: send these to our AuthenticationFilter
	      .addFilterBefore(new AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	  }
  
	  
	  @Bean
	  CorsConfigurationSource corsConfigurationSource() {
		  
		  //Allows us to register path patterns for a CorsConfiguration object (below)
		  UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    
		  //A container for cors configuration, and supporting methods
		  CorsConfiguration config = new CorsConfiguration();
		
		  config.setAllowedOrigins(Arrays.asList("*"));
		  config.setAllowedMethods(Arrays.asList("*"));
		  config.setAllowedHeaders(Arrays.asList("*"));
		  config.setAllowCredentials(true);				//"true" means user credentials are supported (default is false)
		  config.applyPermitDefaultValues();			//By default, a CorsConfiguration does not allow any cross-origin requests. This method flips the initialization model to allow everything. 
	      
	      source.registerCorsConfiguration("/**", config);
	      return source;
	}	
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
	}

}




/*
@Bean
public UserDetailsService userDetailsService() {
	
	UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();
	
	return new InMemoryUserDetailsManager(user);
} */
