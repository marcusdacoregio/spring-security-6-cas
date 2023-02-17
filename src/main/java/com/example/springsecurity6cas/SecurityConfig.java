package com.example.springsecurity6cas;

import org.apereo.cas.client.session.SingleSignOutFilter;
import org.apereo.cas.client.validation.Cas20ServiceTicketValidator;
import org.apereo.cas.client.validation.TicketValidator;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, UserDetailsService userDetailsService) throws Exception {
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				.exceptionHandling((exceptions) -> exceptions
						.authenticationEntryPoint(casAuthenticationEntryPoint())
				)
				.logout((logout) -> logout
						.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
						.logoutSuccessUrl("/logout-success")
				)
				.addFilter(casAuthenticationFilter(userDetailsService))
				.addFilterBefore(new SingleSignOutFilter(), CasAuthenticationFilter.class)
				.addFilterBefore(requestSingleLogoutFilter(), LogoutFilter.class);
		return http.build();
	}

	public LogoutFilter requestSingleLogoutFilter() {
		LogoutFilter logoutFilter = new LogoutFilter("https://localhost:8443/cas/logout", new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl("/logout/cas");
		return logoutFilter;
	}

	public CasAuthenticationProvider casAuthenticationProvider(UserDetailsService userDetailsService) {
		CasAuthenticationProvider provider = new CasAuthenticationProvider();
		provider.setAuthenticationUserDetailsService(new UserDetailsByNameServiceWrapper<>(userDetailsService));
		provider.setServiceProperties(serviceProperties());
		provider.setTicketValidator(cas20ServiceTicketValidator());
		provider.setKey("key");
		return provider;
	}

	private TicketValidator cas20ServiceTicketValidator() {
		return new Cas20ServiceTicketValidator("https://localhost:8443/cas");
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder().username("casuser").password("Mellon").roles("USER").build();
		return new InMemoryUserDetailsManager(user);
	}

	public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
		CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
		casAuthenticationEntryPoint.setLoginUrl("https://localhost:8443/cas/login");
		casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
		return casAuthenticationEntryPoint;
	}

	public CasAuthenticationFilter casAuthenticationFilter(UserDetailsService userDetailsService) {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		CasAuthenticationProvider casAuthenticationProvider = casAuthenticationProvider(userDetailsService);
		filter.setAuthenticationManager(new ProviderManager(casAuthenticationProvider));
		return filter;
	}

	public ServiceProperties serviceProperties() {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://localhost:8081/login/cas");
		serviceProperties.setSendRenew(false);
		return serviceProperties;
	}

}
