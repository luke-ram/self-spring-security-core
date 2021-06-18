package io.security.corespringsecurity.security.service;


import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collection;

public class AccountContext extends User implements Serializable {

    private Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(),authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
