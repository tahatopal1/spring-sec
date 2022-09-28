package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

//@Configuration
//@EnableWebSecurity
public class SecurityConfigSHA256 extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        return new StandardPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(expressionInterceptUrlRegistry -> {
            expressionInterceptUrlRegistry
                    .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                    .antMatchers("/beers/find", "/beers*").permitAll()
                    .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                    .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
//                    .antMatchers("/beers/**").permitAll();
        })
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("db265dc5ae91208bb647f17b65cd478dedf3ff2c466e38f553c06dd5e125b81e7fa0bf7c4ab5a936") // With SHA-256 encoder
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("db265dc5ae91208bb647f17b65cd478dedf3ff2c466e38f553c06dd5e125b81e7fa0bf7c4ab5a936")
                .roles("USER");


        auth.inMemoryAuthentication()
                .withUser("scott")
                .password("{noop}tiger")
                .roles("CUSTOMER");
    }

    //    Doing the same thing above
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("master")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }
}
