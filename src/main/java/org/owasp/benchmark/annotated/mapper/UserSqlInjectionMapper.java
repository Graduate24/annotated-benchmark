package org.owasp.benchmark.annotated.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.owasp.benchmark.annotated.entity.User;

import java.util.List;
import java.util.Map;

/**
 * SQL注入测试用例的Mapper接口
 */
@Mapper
public interface UserSqlInjectionMapper {

    // XML中定义的方法
    List<User> findUsersByNameUnsafe(@Param("username") String username);
    List<User> findUsersByNameSafe(@Param("username") String username);
    List<User> findUsersSortedUnsafe(@Param("sortField") String sortField);
    List<User> findUsersSortedSafe(@Param("sortField") String sortField);
    List<User> findUsersInListUnsafe(@Param("idList") String idList);
    List<User> findUsersInListSafe(@Param("idList") List<Integer> idList);
    List<User> findUsersByMultipleConditionsUnsafe(@Param("whereClause") String whereClause);
    List<User> findUsersByMultipleConditionsSafe(@Param("id") Integer id, @Param("username") String username, @Param("email") String email);
    List<User> findUsersWithLimitUnsafe(@Param("limit") String limit, @Param("offset") String offset);
    List<User> findUsersWithLimitSafe(@Param("limit") int limit, @Param("offset") int offset);
    int updateUserDynamicUnsafe(@Param("id") int id, @Param("setClause") String setClause);
    int updateUserDynamicSafe(@Param("id") int id, @Param("username") String username, @Param("email") String email, @Param("password") String password);
    int deleteUsersUnsafe(@Param("condition") String condition);
    int deleteUsersSafe(@Param("id") Integer id);
    
    // 注解中定义的不安全方法
    @Select("SELECT * FROM users WHERE email = '${email}'")
    User findUserByEmailUnsafe(@Param("email") String email);
    
    // 注解中定义的安全方法
    @Select("SELECT * FROM users WHERE email = #{email}")
    User findUserByEmailSafe(@Param("email") String email);
    
    // 更多注解中定义的不安全方法
    @Select("SELECT * FROM users WHERE username = '${username}' AND password = '${password}'")
    User findUserByCredentialsUnsafe(@Param("username") String username, @Param("password") String password);
    
    // 注解中定义的安全方法
    @Select("SELECT * FROM users WHERE username = #{username} AND password = #{password}")
    User findUserByCredentialsSafe(@Param("username") String username, @Param("password") String password);
    
    // LIKE子句中的不安全方法
    @Select("SELECT * FROM users WHERE ${column} LIKE '%${value}%'")
    List<User> searchUsersUnsafe(@Param("column") String column, @Param("value") String value);
    
    // 安全的LIKE查询
    @Select("SELECT * FROM users WHERE ${column} LIKE CONCAT('%', #{value}, '%')")
    List<User> searchUsersSemiSafe(@Param("column") String column, @Param("value") String value);
    
    // 使用完全安全的LIKE查询
    @Select("<script>"
            + "SELECT * FROM users "
            + "<where>"
            + "<if test=\"column == 'username'\"> username LIKE '%'||#{value}||'%' </if>"
            + "<if test=\"column == 'email'\"> email LIKE '%'||#{value}||'%' </if>"
            + "</where>"
            + "</script>")
    List<User> searchUsersSafe(@Param("column") String column, @Param("value") String value);
} 