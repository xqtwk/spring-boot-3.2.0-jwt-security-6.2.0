package com.xqtwk.token;

import com.xqtwk.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // think about it
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue
    private long id;
    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType; // public? ATTENTION

    public boolean expired;
    public boolean revoked;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public User user;

}
