package com.rbiedrawa.oauth.config;

import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfiguration {

	private final Map<String, Mono<ReactiveAuthenticationManager>> authenticationManagers = new ConcurrentHashMap<>();

	private Mono<ReactiveAuthenticationManager> addManager(String issuer, WebClient webClient) {
		return Mono.fromCallable(() -> buildJwtDecoders(issuer, webClient))
				.subscribeOn(Schedulers.boundedElastic())
				.map(JwtReactiveAuthenticationManager::new);
	}

	private ReactiveJwtDecoder buildJwtDecoders(String issuer, WebClient webClient) {
		Assert.hasText(issuer, "issuer cannot be empty");
		OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(issuer);
		NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder
				.withJwkSetUri(issuer + "/protocol/openid-connect/certs")
				.webClient(webClient)
				.build();
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

	//not need
	@Bean
	JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver(WebClient webClient) {
		return new JwtIssuerReactiveAuthenticationManagerResolver(issue -> authenticationManagers.computeIfAbsent(issue, key -> addManager(issue, webClient)));
	}

	@Bean
	@SneakyThrows
	public WebClient webClient() {
		HttpClient httpClient = HttpClient.create()
				.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
				.responseTimeout(Duration.ofMillis(5000))
				.doOnConnected(conn ->
						conn.addHandlerLast(new ReadTimeoutHandler(5000, TimeUnit.MILLISECONDS))
								.addHandlerLast(new WriteTimeoutHandler(5000, TimeUnit.MILLISECONDS)));

		SslContext sslContext = SslContextBuilder
				.forClient()
				.trustManager(InsecureTrustManagerFactory.INSTANCE)
				.build();
		httpClient = httpClient.secure(t -> t.sslContext(sslContext));

		httpClient.warmup().block();

		return WebClient.builder()
				.clientConnector(new ReactorClientHttpConnector(httpClient))
				.defaultHeader("Content-Type", "application/json")
				.build();
	}
	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
													 @Autowired(required = false) JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver,
													 Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter) {
		// @formatter:off
		http.authorizeExchange()
				.pathMatchers("/by/**").permitAll()
				.pathMatchers("/hello/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
				.anyExchange().authenticated()
			.and()
			.oauth2ResourceServer()
			.jwt()
			.jwtAuthenticationConverter(jwtAuthenticationConverter)
			//uncommit for turn on multi tenant mode
//			.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver))
		;
		// @formatter:on

		return http.build();
	}
}
