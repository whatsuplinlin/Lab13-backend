package se331.rest.security.controller;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.filter.OncePerRequestFilter;
import se331.rest.security.util.JwtTokenUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Service
@Slf4j
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private final Log logger = LogFactory.getLog(this.getClass());

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Value("${jwt.header}")
    private String tokenHeader;

    @Override
    @Transactional
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String authToken = request.getHeader(this.tokenHeader);

        if (authToken != null && authToken.startsWith("Bearer ")) {
            authToken = authToken.substring(7);
        }

        String username = jwtTokenUtil.getUsernameFromToken(authToken);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // It is not compelling necessary to load the use details from the database. You could also store the information
            // in the token and read it from it. It's up to you ;)
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // For simple validation it is completely sufficient to just check the token integrity. You don't have to call
            // the database compellingly. Again it's up to you ;)
            if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info("authenticated user " + username + ", setting security context");
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }
}