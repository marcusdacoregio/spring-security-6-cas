package com.example.springsecurity6cas;

import org.apereo.cas.client.session.SingleSignOutFilter;
import org.apereo.cas.client.validation.Cas20ServiceTicketValidator;
import org.apereo.cas.client.validation.TicketValidator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Value("${cas.base.url}")
	private String casBaseUrl;

	@Value("${cas.login.url}")
	private String casLoginUrl;

	@Autowired
	private ServletWebServerApplicationContext context;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, UserDetailsService userDetailsService) throws Exception {
		http
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers(HttpMethod.GET, "/loggedout").permitAll()
						.anyRequest().authenticated()
				)
				.exceptionHandling((exceptions) -> exceptions
						.authenticationEntryPoint(casAuthenticationEntryPoint())
				)
				.logout((logout) -> logout
						.logoutSuccessUrl("/loggedout")
				)
				.addFilter(casAuthenticationFilter(userDetailsService))
				.addFilterBefore(new SingleSignOutFilter(), CasAuthenticationFilter.class);
		return http.build();
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
		return new Cas20ServiceTicketValidator(this.casBaseUrl);
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder().username("casuser").password("Mellon").roles("USER").build();
		return new InMemoryUserDetailsManager(user);
	}

	public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
		CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
		casAuthenticationEntryPoint.setLoginUrl(this.casLoginUrl);
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
		serviceProperties.setService("http://localhost:" + context.getWebServer().getPort() + "/login/cas");
		serviceProperties.setSendRenew(false);
		return serviceProperties;
	}

}
