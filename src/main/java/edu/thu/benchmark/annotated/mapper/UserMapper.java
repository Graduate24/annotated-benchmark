package edu.thu.benchmark.annotated.mapper;

import org.apache.ibatis.annotations.*;
import edu.thu.benchmark.annotated.entity.User;

import java.util.List;

/**
 * 用户数据访问Mapper接口
 * 包含SQL注入漏洞的示例
 */
public interface UserMapper {

    /**
     * 根据ID查询用户
     */
    @Select("SELECT * FROM users WHERE id = #{id}")
    User getUserById(Integer id);

    /**
     * 根据用户名查询用户 - 安全方式（使用参数绑定）
     */
    @Select("SELECT * FROM users WHERE username = #{username}")
    User getUserByUsername(String username);

    /**
     * 根据邮箱查询用户 - 不安全方式（使用字符串拼接）
     * 这里故意引入SQL注入漏洞
     * CWE-89: SQL注入
     */
    @Select("SELECT * FROM users WHERE email = '${email}'")
    User getUserByEmail(String email);

    /**
     * 查询所有用户
     */
    @Select("SELECT * FROM users")
    List<User> getAllUsers();

    /**
     * 根据条件动态查询用户 - 不安全方式
     * CWE-89: SQL注入
     */
    @Select("SELECT * FROM users WHERE ${condition}")
    List<User> findUsersByCondition(String condition);

    /**
     * 插入用户
     */
    @Insert("INSERT INTO users (username, password, email) VALUES (#{username}, #{password}, #{email})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insertUser(User user);

    /**
     * 更新用户信息 - 不安全方式
     * CWE-89: SQL注入
     */
    @Update("UPDATE users SET ${updateFields} WHERE id = #{id}")
    int updateUser(@Param("id") Integer id, @Param("updateFields") String updateFields);

    /**
     * 删除用户
     */
    @Delete("DELETE FROM users WHERE id = #{id}")
    int deleteUser(Integer id);
}
