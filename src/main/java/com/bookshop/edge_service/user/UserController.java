package com.bookshop.edge_service.user;

import org.springframework.web.bind.annotation.PostMapping;
import reactor.core.publisher.Mono;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@GetMapping("user")
	public Mono<User> getUser(@AuthenticationPrincipal OidcUser oidcUser) {
		var user = new User(
                oidcUser.getSubject(),
				oidcUser.getPreferredUsername(),
				oidcUser.getGivenName(),
				oidcUser.getFamilyName(),
                oidcUser.getEmail(),
				oidcUser.getClaimAsStringList("roles")
		);
		return Mono.just(user);
	}

    @PostMapping("test")
    public Mono<String> test() {
        return Mono.just("xin chao");
    }


}
