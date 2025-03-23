package edu.thu.benchmark.annotated.service.impl;

import edu.thu.benchmark.annotated.entity.User;
import edu.thu.benchmark.annotated.mapper.UserMapper;
import edu.thu.benchmark.annotated.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 用户服务实现类
 */
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public User getUserById(Integer id) {
        return userMapper.getUserById(id);
    }

    @Override
    public User getUserByUsername(String username) {
        return userMapper.getUserByUsername(username);
    }

    @Override
    public User getUserByEmail(String email) {
        return userMapper.getUserByEmail(email);
    }

    @Override
    public List<User> getAllUsers() {
        return userMapper.getAllUsers();
    }

    @Override
    public List<User> findUsersByCondition(String condition) {
        return userMapper.findUsersByCondition(condition);
    }

    @Override
    public int insertUser(User user) {
        return userMapper.insertUser(user);
    }

    @Override
    public int updateUser(Integer id, String updateFields) {
        return userMapper.updateUser(id, updateFields);
    }

    @Override
    public int deleteUser(Integer id) {
        return userMapper.deleteUser(id);
    }
}
