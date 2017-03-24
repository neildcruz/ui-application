package com.demo.microservices.ui.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("user").password("password").roles("USER").build());
		return manager;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.rememberMe().rememberMeParameter("remember-me").and().authorizeRequests().antMatchers("/public/**", "/webjars/**").permitAll().anyRequest().authenticated().and()
				.formLogin().loginPage("/public/login.html").loginProcessingUrl("/login")
				.defaultSuccessUrl("/index.html").and().csrf().disable();
		
	}
}
