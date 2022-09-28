package guru.sfg.brewery.config;

import guru.sfg.brewery.security.CustomPasswordEncoderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
//                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers("/beers/find", "/beers/{beerId}")
                                .hasAnyRole("ADMIN", "CUSTOMER", "USER")
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").hasAnyRole("ADMIN", "CUSTOMER", "USER")
//                            .antMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN") // Added pre-authorize annotation
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}")
                                .hasAnyRole("ADMIN", "CUSTOMER", "USER")
//                            .antMatchers("/brewery/breweries").hasRole("CUSTOMER")
                            .antMatchers("/brewery/breweries")
                                .hasAnyRole("ADMIN", "CUSTOMER")
//                            .antMatchers(HttpMethod.GET, "/brewery/api/v1/breweries").hasRole("CUSTOMER");
                            .antMatchers(HttpMethod.GET, "/brewery/api/v1/breweries")
                                .hasAnyRole("ADMIN", "CUSTOMER");
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic()
                .and().csrf().disable();

        //h2 console config
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return CustomPasswordEncoderFactory.createDelegatingPasswordEncoder();
    }

}
