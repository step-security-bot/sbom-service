package org.openeuler.sbom.manager.service;

import org.openeuler.sbom.manager.model.UserEntity;

import java.util.List;

public interface UserService {

    void addNewUserByNameAndEmail(String name, String email);

    void addNewUserByEntity(UserEntity user);

    Iterable<UserEntity> getAllUsers();

    void deleteAllUsers();

    List<UserEntity> findByUserName1(String name);

    List<UserEntity> findByUserName2(String name);

    List<UserEntity> findByUserName3(String name);
}
