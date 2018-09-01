package com.arman.armaNote.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
		
	/*
	// Authentication : User --> Roles
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.inMemoryAuthentication().withUser("user1").password("{noop}arman123")
				.roles("USER").and().withUser("admin1").password("{noop}arman123")
				.roles("USER", "ADMIN");
	}

	// Authorization : Role -> Access
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic()
			.and()
			.authorizeRequests()
			.antMatchers("/webservice/**").hasRole("USER")
			.antMatchers("/**").hasRole("ADMIN")
			.and()
			.csrf().disable()
			.headers().frameOptions().disable();
	}
	*/
	
	/*
	@Autowired
    private MyAccessDeniedHandler accessDeniedHandler;

    // roles admin allow to access /admin/**
    // roles user allow to access /user/**
    // custom 403 access denied handler
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .csrf().disable()
                .authorizeRequests()
					.antMatchers("/", "/home", "/about").permitAll()
					.antMatchers("/admin/**").hasRole("ADMIN")
					.antMatchers("/user/**").hasRole("USER")
					.antMatchers("/webservice/**").hasRole("VISITOR")
					.anyRequest().authenticated()
                .and()
                .formLogin()
					.loginPage("/login")
					.permitAll()
					.and()
                .logout()
					.permitAll()
					.and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
    }

    // create two users, admin and user
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}arman1").roles("USER")
                .and()
                .withUser("admin").password("{noop}arman2").roles("ADMIN")
                .and()
                .withUser("visitor").password("{noop}arman3").roles("VISITOR");
    }
    */
    
    
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private DataSource dataSource;
	
	@Bean
	CorsFilter corsFilter() {
		CorsFilter filter = new CorsFilter();
	    return filter;
	}
	 
	@Bean
    public JwtAuthenticationFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationFilter();
    }
	
	
	//https://stackoverflow.com/questions/37970709/could-not-autowire-field-private-org-springframework-security-authentication-au
	@Bean
	public AuthenticationManager customAuthenticationManager() throws Exception {
	  return authenticationManager();
	}
	
	@Value("${spring.queries.users-query}")
	private String userQuery;
	
	@Value("${spring.queries.users-by-username-query}")
	private String usernameQuery;
	
	@Value("${spring.queries.roles-query}")
	private String rolesQuery;
	
	@Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
				.usersByUsernameQuery(userQuery)
				.authoritiesByUsernameQuery(rolesQuery)
				.dataSource(dataSource)
				.passwordEncoder(bCryptPasswordEncoder);
		
		
		// this is just a trick to login trough username. But not the correct way. (Change it later)
		// Better to customize userDetailsService's loadUserByUsername(String username) method.
		// means, create own class, extend with userDetailsServiceImpl, then override loadUserByUsername method to get user by using both email and username
		// https://stackoverflow.com/questions/14122756/spring-security-using-both-username-or-email
		auth.jdbcAuthentication()
		.usersByUsernameQuery(usernameQuery)
		.authoritiesByUsernameQuery(rolesQuery)
		.dataSource(dataSource)
		.passwordEncoder(bCryptPasswordEncoder);
	}
	
	public void configure(HttpSecurity http) throws Exception {
		http
		.httpBasic()
		.and()
		.addFilterBefore(corsFilter(), SessionManagementFilter.class) //adds your custom CorsFilter
        .authorizeRequests()
				.antMatchers("/").permitAll()
				.antMatchers("/token/*", "/login").permitAll()
				.antMatchers("/registration").permitAll()
				//.antMatchers("/webservice/**").permitAll()
				.antMatchers("/webservice/**").hasAnyAuthority("ADMIN","WEBSERVICE","USER") // gave rights to user also so that we can make webservice calls from ajax
				.antMatchers("/admin/**").hasAuthority("ADMIN")
				.antMatchers("/user/**").hasAnyAuthority("ADMIN","USER")
				.anyRequest().authenticated()
				.and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and().csrf().disable()
				.formLogin().loginPage("/login")
				.failureUrl("/login?error=true")
				.defaultSuccessUrl("/user/home")
				.usernameParameter("email")
				.passwordParameter("password")
				.and().logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessUrl("/").and().exceptionHandling()
				.accessDeniedPage("/access-denied")
				.and()
				.headers().frameOptions().sameOrigin(); // this last line is added bcz otherwise I was getting "X-frame-option set to deny" error in iframe. So I followed: https://docs.spring.io/spring-security/site/docs/current/reference/html/headers.html
		
		http
        .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
	}
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    	// this portion is added after reading https://stackoverflow.com/questions/24726218/spring-security-refused-to-execute-script-from
    	// and https://stackoverflow.com/questions/24916894/serving-static-web-resources-in-spring-boot-spring-security-application/24920752#24920752
    	web.ignoring().antMatchers("/js/**").antMatchers("/css/**"); // can add more directories later.
    }
    
    
    @Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
    	BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    	return bCryptPasswordEncoder;
    }
    
    // to see spring-angular integration, go through: http://javasampleapproach.com/java-integration/integrate-angular-4-springboot-web-app-springtoolsuite
    
    // to implement jwt, go through https://medium.com/@nydiarra/secure-a-spring-boot-rest-api-with-json-web-token-reference-to-angular-integration-e57a25806c50
    

}
