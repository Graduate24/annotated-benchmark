package edu.thu.benchmark.annotated.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * SQL注入测试切面
 * 使用Before和After注解简化切面实现
 */
@Aspect
@Component
public class SqlInjectionAspect {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * 定义切入点：所有使用CustomSqlExecution注解的方法
     */
    @Pointcut("execution(* edu.thu.benchmark.annotated.service.SqlInjectionTestService.findUsersByAspectSafe(..))")
    public void sqlInjectionServiceMethods() {
    }

    /**
     * 在方法执行前执行不安全的SQL注入操作
     */
    @Before("sqlInjectionServiceMethods()")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在AOP切面中通过字符串拼接构造不安全的SQL查询",
            remediation = "使用参数化查询替代字符串拼接",
            level = VulnerabilityLevel.CRITICAL
    )
    public void beforeUnsafeSqlExecution() {
        // 不安全的SQL查询示例
        String username = "1; delete from users where id = 1";
        String unsafeSql = "SELECT * FROM users WHERE username = '" + username + "'";
        // 记录不安全的SQL注入操作
        System.out.println("执行不安全的SQL查询: " + unsafeSql);

    }

    /**
     * 在方法执行后执行安全的SQL查询操作
     */
    @After("sqlInjectionServiceMethods()")
    public void afterSafeSqlExecution() {
        // 安全的SQL查询示例

        // 使用参数化查询
        String safeSql = "SELECT * FROM users WHERE username = ran";
        List<Map<String, Object>> result = jdbcTemplate.queryForList(safeSql);
        // 记录安全的SQL查询操作
        System.out.println("执行安全的SQL查询：参数化查询");

    }

    /**
     * 针对findUsersByAspectUnsafe方法的特定切面
     */
    @Before("sqlInjectionServiceMethods()")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在Before切面中直接执行不安全的SQL查询",
            remediation = "使用参数化查询替代字符串拼接",
            level = VulnerabilityLevel.CRITICAL
    )
    public List<Map<String, Object>> executeUnsafeSql(String name) {
        // 直接执行不安全的SQL查询
        String username = "1; delete from users where id = 1";
        String unsafeSql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
        return jdbcTemplate.queryForList(name);
    }

    /**
     * 针对findUsersByAspectSafe方法的特定切面
     */
    @Before("sqlInjectionServiceMethods()")
    public List<Map<String, Object>> executeSafeSql() {
        // 执行安全的SQL查询
        String username = "1";
        String safeSql = "SELECT * FROM users WHERE username LIKE CONCAT('%', ?, '%')";
        return jdbcTemplate.queryForList(safeSql, username);
    }
}
