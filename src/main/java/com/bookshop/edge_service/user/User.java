package com.bookshop.edge_service.user;

import java.util.List;

public record User(
        String id,
	String username,
	String firstName,
	String lastName,
    String email,
	List<String> roles
){}
