package org.bci.entities;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Cascade;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static javax.persistence.FetchType.LAZY;
import static org.hibernate.annotations.CascadeType.MERGE;
import static org.hibernate.annotations.CascadeType.PERSIST;
import static org.hibernate.annotations.CascadeType.REMOVE;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
@Setter
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.AUTO)
    UUID id;

    String name;

    @Column(nullable = false, unique = true)
    String email;

    String password;

    Instant created;

    @OneToMany(fetch = LAZY, targetEntity = PhoneEntity.class)
    @Cascade({REMOVE, MERGE, PERSIST})
    @JoinColumn(name = "user_id")
    List<PhoneEntity> phones;

}
