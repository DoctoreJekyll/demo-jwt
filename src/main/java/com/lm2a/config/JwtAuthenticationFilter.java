package com.lm2a.config;

import com.lm2a.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //1. verificar que el token existe. Si no existe seguir la cadena de filtro pero impedir el acceso
        final String token = getTokenFromRequest(request);

        if(token == null){
            filterChain.doFilter(request,response);
            return;
        }

        //2. extraer el username del token
        String username = jwtService.extractUsername(token);

        //3. con el username buscar en el security context si es que ya existe, no hay nada que hacer, salvo continuar la cadena de filtros
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //4. si no esta en contexto de seguridad ver si existe en nuestra BBDD de usuarios
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            //5. verificar que el token sea valido
            if(jwtService.isTokenValid(token, userDetails)){
                //6. crear el objeto authentication y meterlo en security context
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request,response);
        }

    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
