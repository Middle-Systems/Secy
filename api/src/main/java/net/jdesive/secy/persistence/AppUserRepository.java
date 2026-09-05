package net.jdesive.secy.persistence;

import net.jdesive.secy.persistence.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.Optional;
import java.util.UUID;

/**
 * Accounts repository.
 *
 * <p>{@code exported = false}: spring-boot-starter-data-rest is on the classpath and would
 * otherwise publish a CRUD endpoint for this repository. Accounts are only ever reachable through
 * {@code /auth/**}.
 */
@RepositoryRestResource(exported = false)
public interface AppUserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
