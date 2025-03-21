package org.owasp.benchmark.annotated.service;

import org.owasp.benchmark.annotated.entity.User;

import java.util.List;

/**
 * 用户服务接口
 */
public interface UserService {

    /**
     * 根据ID查询用户
     */
    User getUserById(Integer id);

    /**
     * 根据用户名查询用户
     */
    User getUserByUsername(String username);

    /**
     * 根据邮箱查询用户
     */
    User getUserByEmail(String email);

    /**
     * 查询所有用户
     */
    List<User> getAllUsers();
    
    /**
     * 根据条件查询用户
     */
    List<User> findUsersByCondition(String condition);

    /**
     * 插入用户
     */
    int insertUser(User user);

    /**
     * 更新用户信息
     */
    int updateUser(Integer id, String updateFields);

    /**
     * 删除用户
     */
    int deleteUser(Integer id);
} 