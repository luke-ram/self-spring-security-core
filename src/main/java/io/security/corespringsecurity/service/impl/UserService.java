package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.Account;
import org.springframework.stereotype.Service;

public interface UserService {

    void createUser(Account account);

}
