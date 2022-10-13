package se331.rest.security.repository;



import org.springframework.data.repository.CrudRepository;
import se331.rest.security.entity.Authority;
import se331.rest.security.entity.AuthorityName;

public interface AuthorityRepository extends CrudRepository<Authority, Long> {
    Authority findByName(AuthorityName input);
}
