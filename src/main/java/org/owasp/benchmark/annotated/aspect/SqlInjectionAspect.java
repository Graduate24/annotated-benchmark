package org.owasp.benchmark.annotated.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.owasp.benchmark.annotated.annotation.Vulnerability;
import org.owasp.benchmark.annotated.annotation.VulnerabilityLevel;
import org.owasp.benchmark.annotated.annotation.VulnerabilityType;
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
    @Pointcut("execution(* org.owasp.benchmark.annotated.service.SqlInjectionTestService.findUsersByAspectSafe(..))")
    public void sqlInjectionServiceMethods() {}
    
    /**
     * 在方法执行前执行不安全的SQL注入操作
     */
    @Before("execution(* org.owasp.benchmark.annotated.service.SqlInjectionTestService.findUsersByAspectSafe(..))")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在AOP切面中通过字符串拼接构造不安全的SQL查询",
            remediation = "使用参数化查询替代字符串拼接",
            level = VulnerabilityLevel.CRITICAL
    )
    public void beforeUnsafeSqlExecution(JoinPoint joinPoint, String username) {
        // 不安全的SQL查询示例
        if (joinPoint.getSignature().getName().contains("Unsafe")) {
            String unsafeSql = "SELECT * FROM users WHERE username = '" + username + "'";
            // 记录不安全的SQL注入操作
            System.out.println("执行不安全的SQL查询: " + unsafeSql);
        }
    }
    
    /**
     * 在方法执行后执行安全的SQL查询操作
     */
    @After("execution(* org.owasp.benchmark.annotated.service.SqlInjectionTestService.findUsersByAspectSafe(..))")
    public void afterSafeSqlExecution(JoinPoint joinPoint, String username) {
        // 安全的SQL查询示例
        if (joinPoint.getSignature().getName().contains("Safe")) {
            // 使用参数化查询
            String safeSql = "SELECT * FROM users WHERE username = ?";
            List<Map<String, Object>> result = jdbcTemplate.queryForList(safeSql, username);
            // 记录安全的SQL查询操作
            System.out.println("执行安全的SQL查询：参数化查询，参数值：" + username);
        }
    }
    
    /**
     * 针对findUsersByAspectUnsafe方法的特定切面
     */
    @Before("execution(* org.owasp.benchmark.annotated.service.SqlInjectionTestService.findUsersByAspectUnsafe(..))")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在Before切面中直接执行不安全的SQL查询",
            remediation = "使用参数化查询替代字符串拼接",
            level = VulnerabilityLevel.CRITICAL
    )
    public List<Map<String, Object>> executeUnsafeSql(JoinPoint joinPoint, String username) {
        // 直接执行不安全的SQL查询
        String unsafeSql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
        return jdbcTemplate.queryForList(unsafeSql);
    }
    
    /**
     * 针对findUsersByAspectSafe方法的特定切面
     */
    @Before("execution(* org.owasp.benchmark.annotated.service.SqlInjectionTestService.findUsersByAspectSafe(..))")
    public List<Map<String, Object>> executeSafeSql(JoinPoint joinPoint, String username) {
        // 执行安全的SQL查询
        String safeSql = "SELECT * FROM users WHERE username LIKE CONCAT('%', ?, '%')";
        return jdbcTemplate.queryForList(safeSql, username);
    }
} 