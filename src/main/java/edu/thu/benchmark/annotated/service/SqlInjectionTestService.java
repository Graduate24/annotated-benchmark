package edu.thu.benchmark.annotated.service;

import edu.thu.benchmark.annotated.aspect.CustomSqlExecution;
import edu.thu.benchmark.annotated.entity.User;
import edu.thu.benchmark.annotated.mapper.UserSqlInjectionMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SQL注入测试服务
 */
@Service
public class SqlInjectionTestService {

    @Autowired
    private UserSqlInjectionMapper userSqlInjectionMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    @Value("${app.database.query.template}")
    private String queryTemplate;

    // MyBatis XML方法 - 不安全
    public List<User> findUsersByNameUnsafe(String username) {
        return userSqlInjectionMapper.findUsersByNameUnsafe(username);
    }

    // MyBatis XML方法 - 安全
    public List<User> findUsersByNameSafe(String username) {
        return userSqlInjectionMapper.findUsersByNameSafe(username);
    }

    // MyBatis XML方法 - ORDER BY注入 - 不安全
    public List<User> findUsersSortedUnsafe(String sortField) {
        return userSqlInjectionMapper.findUsersSortedUnsafe(sortField);
    }

    // MyBatis XML方法 - ORDER BY注入 - 安全
    public List<User> findUsersSortedSafe(String sortField) {
        return userSqlInjectionMapper.findUsersSortedSafe(sortField);
    }

    // MyBatis XML方法 - IN子句注入 - 不安全
    public List<User> findUsersInListUnsafe(String idList) {
        return userSqlInjectionMapper.findUsersInListUnsafe(idList);
    }

    // MyBatis XML方法 - IN子句注入 - 安全
    public List<User> findUsersInListSafe(List<Integer> idList) {
        return userSqlInjectionMapper.findUsersInListSafe(idList);
    }

    // MyBatis XML方法 - 多条件查询 - 不安全
    public List<User> findUsersByMultipleConditionsUnsafe(String whereClause) {
        return userSqlInjectionMapper.findUsersByMultipleConditionsUnsafe(whereClause);
    }

    // MyBatis XML方法 - 多条件查询 - 安全
    public List<User> findUsersByMultipleConditionsSafe(Integer id, String username, String email) {
        return userSqlInjectionMapper.findUsersByMultipleConditionsSafe(id, username, email);
    }

    // MyBatis XML方法 - LIMIT/OFFSET注入 - 不安全
    public List<User> findUsersWithLimitUnsafe(String limit, String offset) {
        return userSqlInjectionMapper.findUsersWithLimitUnsafe(limit, offset);
    }

    // MyBatis XML方法 - LIMIT/OFFSET注入 - 安全
    public List<User> findUsersWithLimitSafe(int limit, int offset) {
        return userSqlInjectionMapper.findUsersWithLimitSafe(limit, offset);
    }

    // MyBatis XML方法 - 动态更新 - 不安全
    public int updateUserDynamicUnsafe(int id, String setClause) {
        return userSqlInjectionMapper.updateUserDynamicUnsafe(id, setClause);
    }

    // MyBatis XML方法 - 动态更新 - 安全
    public int updateUserDynamicSafe(int id, String username, String email, String password) {
        return userSqlInjectionMapper.updateUserDynamicSafe(id, username, email, password);
    }

    // MyBatis XML方法 - 条件删除 - 不安全
    public int deleteUsersUnsafe(String condition) {
        return userSqlInjectionMapper.deleteUsersUnsafe(condition);
    }

    // MyBatis XML方法 - 条件删除 - 安全
    public int deleteUsersSafe(Integer id) {
        return userSqlInjectionMapper.deleteUsersSafe(id);
    }

    // MyBatis注解方法 - 不安全
    public User findUserByEmailUnsafe(String email) {
        return userSqlInjectionMapper.findUserByEmailUnsafe(email);
    }

    // MyBatis注解方法 - 安全
    public User findUserByEmailSafe(String email) {
        return userSqlInjectionMapper.findUserByEmailSafe(email);
    }

    // MyBatis注解方法 - 不安全
    public User findUserByCredentialsUnsafe(String username, String password) {
        return userSqlInjectionMapper.findUserByCredentialsUnsafe(username, password);
    }

    // MyBatis注解方法 - 安全
    public User findUserByCredentialsSafe(String username, String password) {
        return userSqlInjectionMapper.findUserByCredentialsSafe(username, password);
    }

    // MyBatis注解方法 - LIKE子句 - 不安全
    public List<User> searchUsersUnsafe(String column, String value) {
        return userSqlInjectionMapper.searchUsersUnsafe(column, value);
    }

    // MyBatis注解方法 - LIKE子句 - 半安全
    public List<User> searchUsersSemiSafe(String column, String value) {
        return userSqlInjectionMapper.searchUsersSemiSafe(column, value);
    }

    // MyBatis注解方法 - LIKE子句 - 安全
    public List<User> searchUsersSafe(String column, String value) {
        return userSqlInjectionMapper.searchUsersSafe(column, value);
    }

    // 原生JDBC - 不安全
    public List<Map<String, Object>> findUsersByJdbcUnsafe(String condition) {
        String sql = "SELECT * FROM users WHERE " + condition;
        return jdbcTemplate.queryForList(sql);
    }

    // 原生JDBC - 安全
    public List<Map<String, Object>> findUsersByJdbcSafe(String username, String email) {
        String sql = "SELECT * FROM users WHERE username = ? OR email = ?";
        return jdbcTemplate.queryForList(sql, username, email);
    }

    // 原生JDBC - 使用配置模板 - 不安全
    public List<Map<String, Object>> findUsersByTemplateUnsafe(String username) {
        String sql = String.format(queryTemplate, username);
        return jdbcTemplate.queryForList(sql);
    }

    // 原生JDBC - 使用配置模板 - 安全
    public List<Map<String, Object>> findUsersByTemplateSafe(String username) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE username = ?", username);
    }

    // NamedParameterJdbcTemplate - 不安全
    public List<Map<String, Object>> findByNamedParamsUnsafe(String whereClause, Map<String, Object> params) {
        String sql = "SELECT * FROM users WHERE " + whereClause;
        return namedParameterJdbcTemplate.queryForList(sql, params);
    }

    // NamedParameterJdbcTemplate - 安全
    public List<Map<String, Object>> findByNamedParamsSafe(Map<String, Object> params) {
        String sql = "SELECT * FROM users WHERE username = :username OR email = :email";
        return namedParameterJdbcTemplate.queryForList(sql, params);
    }

    // 使用切面执行SQL - 不安全
    @CustomSqlExecution(
            sql = "SELECT * FROM users WHERE username LIKE '%:username%'",
            paramNames = {"username"},
            safe = false
    )
    public List<Map<String, Object>> findUsersByAspectUnsafe(String username) {
        // 实际方法体会被切面替换，这里的实现不会执行
        return null;
    }

    // 使用切面执行SQL - 安全
    @CustomSqlExecution(
            sql = "SELECT * FROM users WHERE username LIKE CONCAT('%', ?, '%')",
            paramNames = {"username"},
            safe = true
    )
    public List<Map<String, Object>> findUsersByAspectSafe(String username) {
        // 使用jdbcTemplate安全实现
        return jdbcTemplate.queryForList(
                "SELECT * FROM users WHERE username LIKE CONCAT('%', ?, '%')",
                username);
    }

    // 新添加的测试方法 - 专门用于测试切面的不安全方法
    public List<Map<String, Object>> testAspectUnsafeMethod(String username) {
        System.out.println("执行testAspectUnsafeMethod方法，参数：" + username);
        // 这个方法的实际执行会被切面拦截
        return null;
    }

    // 新添加的测试方法 - 专门用于测试切面的安全方法
    public List<Map<String, Object>> testAspectSafeMethod(String username) {
        System.out.println("执行testAspectSafeMethod方法，参数：" + username);
        // 这个方法的实际执行会被切面拦截
        return null;
    }
}
