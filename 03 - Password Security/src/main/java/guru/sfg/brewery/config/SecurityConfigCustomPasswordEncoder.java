package guru.sfg.brewery.config;

import guru.sfg.brewery.security.CustomPasswordEncoderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfigCustomPasswordEncoder extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return CustomPasswordEncoderFactory.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$10$tbFs8eAGPBfaS7W/ppBkdeU7mn4ChBOQ6j.hIa3Tc4Sicozzh.ELC")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{sha256}94a9720466abb0ea1fec5c362a85bbd2deca8ff850579dd9ccb1204484f217819fb26f626f01b344")
                .roles("USER");

        auth.inMemoryAuthentication().withUser("scott").password("{bcrypt15}$2a$15$JFnO8HVGHUl9gFfFWfa93ONtPEAhmVMZcCzaEOy7Yikjj11ZQ3OQ2").roles("CUSTOMER");
    }
}
