package se331.rest.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import se331.rest.security.entity.User;


public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
