package com.rbiedrawa.oauth.config.jwtdecoder;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//uncommit for turn on multitenant mode
//@Component
public class MultiKeyReactiveJwtDecoder implements ReactiveJwtDecoder {

    private final ReactiveJwtDecoder reactiveJwtDecoder;
    private final Map<String, Converter<JWT, Mono<JWTClaimsSet>>> reactiveRemoteJWKSources = new HashMap<>();
    private final WebClient webClient;

    public MultiKeyReactiveJwtDecoder(WebClient webClient) {
        this.reactiveJwtDecoder = new NimbusReactiveJwtDecoder(jwt -> {
            String issuer = getIssuer(jwt);
        //todo thread-safe
            if (reactiveRemoteJWKSources.containsKey(issuer)) {
                return reactiveRemoteJWKSources.get(issuer).convert(jwt);
            }

            Converter<JWT, Mono<JWTClaimsSet>> converter = buildConverter(issuer);

            reactiveRemoteJWKSources.put(issuer, converter);
            return converter.convert(jwt);
        });
        this.webClient = webClient;
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        return reactiveJwtDecoder.decode(token);
    }

    private Converter<JWT, Mono<JWTClaimsSet>> buildConverter(String issue) {
        JWKSecurityContextJWKSet jwkSource = new JWKSecurityContextJWKSet();
        DefaultJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<JWKSecurityContext> jwsKeySelector = jwsKeySelector(jwkSource);
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        ReactiveRemoteJWKSource source = new ReactiveRemoteJWKSource(this.webClient, issue);
        Function<JWSAlgorithm, Boolean> expectedJwsAlgorithms = getExpectedJwsAlgorithms(jwsKeySelector);
        return (jwt) -> {
            JWKSelector selector = createSelector(expectedJwsAlgorithms, jwt.getHeader());
            return source.get(selector)
                    .onErrorMap((ex) -> new IllegalStateException("Could not obtain the keys", ex))
                    .map((jwkList) -> createClaimsSet(jwtProcessor, jwt, new JWKSecurityContext(jwkList)));
        };
    }

    private JWSKeySelector<JWKSecurityContext> jwsKeySelector(JWKSource<JWKSecurityContext> jwkSource) {
        return new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        /*if (this.signatureAlgorithms.isEmpty()) {
            return new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        }
        Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
        for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
            jwsAlgorithms.add(jwsAlgorithm);
        }
        return new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);*/
    }

    private Function<JWSAlgorithm, Boolean> getExpectedJwsAlgorithms(JWSKeySelector<?> jwsKeySelector) {
        if (jwsKeySelector instanceof JWSVerificationKeySelector) {
            return ((JWSVerificationKeySelector<?>) jwsKeySelector)::isAllowed;
        }
        throw new IllegalArgumentException("Unsupported key selector type " + jwsKeySelector.getClass());
    }

    private JWKSelector createSelector(Function<JWSAlgorithm, Boolean> expectedJwsAlgorithms, Header header) {
        JWSHeader jwsHeader = (JWSHeader) header;
        if (!expectedJwsAlgorithms.apply(jwsHeader.getAlgorithm())) {
            throw new BadJwtException("Unsupported algorithm of " + header.getAlgorithm());
        }
        return new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
    }

    private static <C extends SecurityContext> JWTClaimsSet createClaimsSet(JWTProcessor<C> jwtProcessor,
                                                                            JWT parsedToken, C context) {
        try {
            return jwtProcessor.process(parsedToken, context);
        }
        catch (BadJOSEException ex) {
            throw new BadJwtException("Failed to validate the token", ex);
        }
        catch (JOSEException ex) {
            throw new JwtException("Failed to validate the token", ex);
        }
    }

    private String getIssuer(JWT source) {
        try {
            JWTClaimsSet jwtClaimsSet = source.getJWTClaimsSet();
            return jwtClaimsSet.getIssuer();
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }
}
