package org.owasp.benchmark.annotated.controller;

import org.owasp.benchmark.annotated.annotation.Vulnerability;
import org.owasp.benchmark.annotated.annotation.VulnerabilityLevel;
import org.owasp.benchmark.annotated.annotation.VulnerabilityType;
import org.owasp.benchmark.annotated.entity.User;
import org.owasp.benchmark.annotated.service.SqlInjectionTestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SQL注入测试控制器
 * 包含40个测试用例，20个正例（存在漏洞）和20个负例（安全实现）
 */
@RestController
@RequestMapping("/sqli")
public class SqlInjectionTestController {
    
    @Autowired
    private SqlInjectionTestService sqlInjectionTestService;
    
    // ======== 测试用例 - 正例（存在SQL注入漏洞） ========
    
    /**
     * 测试用例1：使用MyBatis XML - LIKE查询 - 不安全实现
     */
    @GetMapping("/01")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用MyBatis XML中的${username}进行字符串拼接，导致SQL注入漏洞",
            remediation = "使用#{username}参数绑定代替${username}字符串拼接",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<User> testCase01(@RequestParam String username) {
        return sqlInjectionTestService.findUsersByNameUnsafe(username);
    }
    
    /**
     * 测试用例2：使用MyBatis XML - ORDER BY子句 - 不安全实现
     */
    @GetMapping("/02")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在ORDER BY子句中使用${sortField}进行字符串拼接，允许注入额外的SQL语句",
            remediation = "使用白名单验证排序字段或使用预编译语句",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public List<User> testCase02(@RequestParam String sortField) {
        return sqlInjectionTestService.findUsersSortedUnsafe(sortField);
    }
    
    /**
     * 测试用例3：使用MyBatis XML - IN子句 - 不安全实现
     */
    @GetMapping("/03")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在IN子句中使用${idList}进行字符串拼接，允许任意SQL注入",
            remediation = "使用<foreach>元素或预处理语句构建IN子句",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<User> testCase03(@RequestParam String idList) {
        return sqlInjectionTestService.findUsersInListUnsafe(idList);
    }
    
    /**
     * 测试用例4：使用MyBatis XML - WHERE子句 - 不安全实现
     */
    @GetMapping("/04")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在WHERE子句中使用${whereClause}进行字符串拼接，允许任意SQL注入",
            remediation = "使用<where>和<if>元素构建动态查询条件",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    public List<User> testCase04(@RequestParam String whereClause) {
        return sqlInjectionTestService.findUsersByMultipleConditionsUnsafe(whereClause);
    }
    
    /**
     * 测试用例5：使用MyBatis XML - LIMIT/OFFSET - 不安全实现
     */
    @GetMapping("/05")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在LIMIT和OFFSET子句中使用${limit}和${offset}进行字符串拼接，允许SQL注入",
            remediation = "使用#{limit}和#{offset}参数绑定，并验证输入是否为数字",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public List<User> testCase05(@RequestParam String limit, @RequestParam String offset) {
        return sqlInjectionTestService.findUsersWithLimitUnsafe(limit, offset);
    }
    
    /**
     * 测试用例6：使用MyBatis XML - SET子句 - 不安全实现
     */
    @PostMapping("/06")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在UPDATE语句的SET子句中使用${setClause}进行字符串拼接，允许任意SQL注入",
            remediation = "使用<set>和<if>元素构建动态更新语句",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public int testCase06(@RequestParam int id, @RequestParam String setClause) {
        return sqlInjectionTestService.updateUserDynamicUnsafe(id, setClause);
    }
    
    /**
     * 测试用例7：使用MyBatis XML - DELETE条件 - 不安全实现
     */
    @DeleteMapping("/07")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在DELETE语句的WHERE子句中使用${condition}进行字符串拼接，允许任意SQL注入",
            remediation = "使用参数绑定和预编译语句执行删除操作",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    public int testCase07(@RequestParam String condition) {
        return sqlInjectionTestService.deleteUsersUnsafe(condition);
    }
    
    /**
     * 测试用例8：使用MyBatis注解 - 不安全实现
     */
    @GetMapping("/08")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在@Select注解中使用${email}进行字符串拼接，允许SQL注入",
            remediation = "使用#{email}参数绑定代替${email}字符串拼接",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public User testCase08(@RequestParam String email) {
        return sqlInjectionTestService.findUserByEmailUnsafe(email);
    }
    
    /**
     * 测试用例9：使用MyBatis注解 - 多参数 - 不安全实现
     */
    @GetMapping("/09")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在@Select注解中对多个参数使用${username}和${password}进行字符串拼接，导致SQL注入",
            remediation = "使用#{username}和#{password}参数绑定代替字符串拼接",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public User testCase09(@RequestParam String username, @RequestParam String password) {
        return sqlInjectionTestService.findUserByCredentialsUnsafe(username, password);
    }
    
    /**
     * 测试用例10：使用MyBatis注解 - LIKE查询 - 不安全实现
     */
    @GetMapping("/10")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在@Select注解的LIKE子句中使用${column}和${value}进行字符串拼接，允许SQL注入",
            remediation = "使用白名单验证列名，并使用参数绑定处理LIKE模式",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<User> testCase10(@RequestParam String column, @RequestParam String value) {
        return sqlInjectionTestService.searchUsersUnsafe(column, value);
    }
    
    /**
     * 测试用例11：原生JDBC - 不安全实现
     */
    @GetMapping("/11")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用JDBC直接拼接查询条件，允许任意SQL注入",
            remediation = "使用PreparedStatement和参数绑定",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    public List<Map<String, Object>> testCase11(@RequestParam String condition) {
        return sqlInjectionTestService.findUsersByJdbcUnsafe(condition);
    }
    
    /**
     * 测试用例12：配置模板字符串 - 不安全实现
     */
    @GetMapping("/12")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用来自配置文件的SQL模板和String.format()进行字符串拼接，允许SQL注入",
            remediation = "使用PreparedStatement和参数绑定代替String.format()",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<Map<String, Object>> testCase12(@RequestParam String username) {
        return sqlInjectionTestService.findUsersByTemplateUnsafe(username);
    }
    
    /**
     * 测试用例13：NamedParameterJdbcTemplate - 不安全实现
     */
    @GetMapping("/13")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用NamedParameterJdbcTemplate但仍然拼接WHERE子句，允许SQL注入",
            remediation = "所有SQL语句都应使用参数化查询，不进行直接拼接",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<Map<String, Object>> testCase13(@RequestParam String whereClause) {
        Map<String, Object> params = new HashMap<>();
        params.put("username", "admin");
        params.put("email", "admin@example.com");
        return sqlInjectionTestService.findByNamedParamsUnsafe(whereClause, params);
    }
    
    /**
     * 测试用例14：使用AOP切面 - 不安全实现
     */
    @GetMapping("/14")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "通过AOP切面执行SQL时使用字符串替换而非参数绑定，允许SQL注入",
            remediation = "使用PreparedStatement和参数绑定代替字符串替换",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<Map<String, Object>> testCase14(@RequestParam String username) {
        return sqlInjectionTestService.findUsersByAspectUnsafe(username);
    }
    
    /**
     * 测试用例15：MyBatis XML - LIKE查询 - 半安全实现
     */
    @GetMapping("/15")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "在LIKE子句中正确使用参数绑定，但列名仍然使用${column}字符串拼接，允许列名注入",
            remediation = "使用白名单验证列名，避免拼接列名",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public List<User> testCase15(@RequestParam String column, @RequestParam String value) {
        return sqlInjectionTestService.searchUsersSemiSafe(column, value);
    }
    
    /**
     * 测试用例16：字符串拼接多个条件 - 不安全实现
     */
    @GetMapping("/16")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "手动拼接多个查询条件，允许SQL注入",
            remediation = "使用参数化查询和动态SQL构建条件",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<User> testCase16(@RequestParam String id, @RequestParam String username) {
        String whereClause = "id = " + id + " OR username LIKE '%" + username + "%'";
        return sqlInjectionTestService.findUsersByMultipleConditionsUnsafe(whereClause);
    }
    
    /**
     * 测试用例17：字符串模板内联SQL - 不安全实现
     */
    @GetMapping("/17")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用Java字符串模板进行SQL拼接，允许SQL注入",
            remediation = "使用参数化查询替代字符串模板",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<Map<String, Object>> testCase17(@RequestParam String id, @RequestParam String username) {
        String condition = "id = " + id + " OR username = '" + username + "'";
        return sqlInjectionTestService.findUsersByJdbcUnsafe(condition);
    }
    
    /**
     * 测试用例18：自定义SQL拼接 - 不安全实现
     */
    @GetMapping("/18")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "手动构建复杂的WHERE子句，允许SQL注入",
            remediation = "使用参数化查询和ORM框架的动态SQL功能",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<User> testCase18(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String sortBy) {
        StringBuilder whereClause = new StringBuilder();
        if (username != null) {
            whereClause.append("username LIKE '%").append(username).append("%'");
        }
        if (email != null) {
            if (whereClause.length() > 0) {
                whereClause.append(" AND ");
            }
            whereClause.append("email LIKE '%").append(email).append("%'");
        }
        if (sortBy != null) {
            whereClause.append(" ORDER BY ").append(sortBy);
        }
        return sqlInjectionTestService.findUsersByMultipleConditionsUnsafe(whereClause.toString());
    }
    
    /**
     * 测试用例19：使用不同的拼接方式 - 不安全实现
     */
    @GetMapping("/19")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用+运算符拼接SQL语句，允许SQL注入",
            remediation = "使用参数化查询和参数绑定",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public User testCase19(@RequestParam String id) {
        String condition = "id = " + id;
        List<User> users = sqlInjectionTestService.findUsersByMultipleConditionsUnsafe(condition);
        return users.isEmpty() ? null : users.get(0);
    }
    
    /**
     * 测试用例20：组合多种不安全方式 - 不安全实现
     */
    @GetMapping("/20")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "组合多种不安全的SQL拼接方式，允许复杂的SQL注入",
            remediation = "使用参数化查询和ORM框架的安全特性",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    public List<User> testCase20(
            @RequestParam String field,
            @RequestParam String value,
            @RequestParam String orderBy,
            @RequestParam String limit) {
        String whereClause = field + " = '" + value + "' ORDER BY " + orderBy + " LIMIT " + limit;
        return sqlInjectionTestService.findUsersByMultipleConditionsUnsafe(whereClause);
    }
    
    // ======== 测试用例 - 负例（安全实现） ========
    
    /**
     * 测试用例21：使用MyBatis XML - LIKE查询 - 安全实现
     */
    @GetMapping("/21")
    public List<User> testCase21(@RequestParam String username) {
        return sqlInjectionTestService.findUsersByNameSafe(username);
    }
    
    /**
     * 测试用例22：使用MyBatis XML - ORDER BY子句 - 安全实现
     */
    @GetMapping("/22")
    public List<User> testCase22(@RequestParam String sortField) {
        return sqlInjectionTestService.findUsersSortedSafe(sortField);
    }
    
    /**
     * 测试用例23：使用MyBatis XML - IN子句 - 安全实现
     */
    @GetMapping("/23")
    public List<User> testCase23(@RequestParam List<Integer> idList) {
        return sqlInjectionTestService.findUsersInListSafe(idList);
    }
    
    /**
     * 测试用例24：使用MyBatis XML - 多条件查询 - 安全实现
     */
    @GetMapping("/24")
    public List<User> testCase24(
            @RequestParam(required = false) Integer id,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email) {
        return sqlInjectionTestService.findUsersByMultipleConditionsSafe(id, username, email);
    }
    
    /**
     * 测试用例25：使用MyBatis XML - LIMIT/OFFSET - 安全实现
     */
    @GetMapping("/25")
    public List<User> testCase25(@RequestParam int limit, @RequestParam int offset) {
        return sqlInjectionTestService.findUsersWithLimitSafe(limit, offset);
    }
    
    /**
     * 测试用例26：使用MyBatis XML - SET子句 - 安全实现
     */
    @PostMapping("/26")
    public int testCase26(
            @RequestParam int id,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String password) {
        return sqlInjectionTestService.updateUserDynamicSafe(id, username, email, password);
    }
    
    /**
     * 测试用例27：使用MyBatis XML - DELETE条件 - 安全实现
     */
    @DeleteMapping("/27")
    public int testCase27(@RequestParam Integer id) {
        return sqlInjectionTestService.deleteUsersSafe(id);
    }
    
    /**
     * 测试用例28：使用MyBatis注解 - 安全实现
     */
    @GetMapping("/28")
    public User testCase28(@RequestParam String email) {
        return sqlInjectionTestService.findUserByEmailSafe(email);
    }
    
    /**
     * 测试用例29：使用MyBatis注解 - 多参数 - 安全实现
     */
    @GetMapping("/29")
    public User testCase29(@RequestParam String username, @RequestParam String password) {
        return sqlInjectionTestService.findUserByCredentialsSafe(username, password);
    }
    
    /**
     * 测试用例30：使用MyBatis注解 - LIKE查询 - 安全实现
     */
    @GetMapping("/30")
    public List<User> testCase30(@RequestParam String column, @RequestParam String value) {
        return sqlInjectionTestService.searchUsersSafe(column, value);
    }
    
    /**
     * 测试用例31：原生JDBC - 安全实现
     */
    @GetMapping("/31")
    public List<Map<String, Object>> testCase31(@RequestParam String username, @RequestParam String email) {
        return sqlInjectionTestService.findUsersByJdbcSafe(username, email);
    }
    
    /**
     * 测试用例32：配置模板字符串 - 安全实现
     */
    @GetMapping("/32")
    public List<Map<String, Object>> testCase32(@RequestParam String username) {
        return sqlInjectionTestService.findUsersByTemplateSafe(username);
    }
    
    /**
     * 测试用例33：NamedParameterJdbcTemplate - 安全实现
     */
    @GetMapping("/33")
    public List<Map<String, Object>> testCase33(@RequestParam String username, @RequestParam String email) {
        Map<String, Object> params = new HashMap<>();
        params.put("username", username);
        params.put("email", email);
        return sqlInjectionTestService.findByNamedParamsSafe(params);
    }
    
    /**
     * 测试用例34：使用AOP切面 - 安全实现
     */
    @GetMapping("/34")
    public List<Map<String, Object>> testCase34(@RequestParam String username) {
        return sqlInjectionTestService.findUsersByAspectSafe(username);
    }
    
    /**
     * 测试用例35：使用预处理语句 - 安全实现
     */
    @GetMapping("/35")
    public List<Map<String, Object>> testCase35(@RequestParam String username, @RequestParam String email) {
        Map<String, Object> params = new HashMap<>();
        params.put("username", username);
        params.put("email", email);
        return sqlInjectionTestService.findByNamedParamsSafe(params);
    }
    
    /**
     * 测试用例36：使用ORM框架安全特性 - 安全实现
     */
    @GetMapping("/36")
    public List<User> testCase36(
            @RequestParam(required = false) Integer id,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email) {
        return sqlInjectionTestService.findUsersByMultipleConditionsSafe(id, username, email);
    }
    
    /**
     * 测试用例37：使用白名单校验 - 安全实现
     */
    @GetMapping("/37")
    public List<User> testCase37(@RequestParam String sortField) {
        // 白名单验证
        List<String> allowedFields = List.of("id", "username", "email");
        if (!allowedFields.contains(sortField)) {
            sortField = "id"; // 默认排序字段
        }
        return sqlInjectionTestService.findUsersSortedSafe(sortField);
    }
    
    /**
     * 测试用例38：使用参数化查询和类型转换 - 安全实现
     */
    @GetMapping("/38")
    public List<User> testCase38(@RequestParam String limitStr, @RequestParam String offsetStr) {
        // 类型转换和边界检查
        int limit;
        int offset;
        try {
            limit = Integer.parseInt(limitStr);
            offset = Integer.parseInt(offsetStr);
        } catch (NumberFormatException e) {
            limit = 10;
            offset = 0;
        }
        
        if (limit <= 0 || limit > 100) limit = 10;
        if (offset < 0) offset = 0;
        
        return sqlInjectionTestService.findUsersWithLimitSafe(limit, offset);
    }
    
    /**
     * 测试用例39：使用参数绑定的IN查询 - 安全实现
     */
    @GetMapping("/39")
    public List<User> testCase39(@RequestParam String idsStr) {
        // 解析ID列表并进行类型转换
        List<Integer> idList = new ArrayList<>();
        String[] idsArray = idsStr.split(",");
        for (String idStr : idsArray) {
            try {
                idList.add(Integer.parseInt(idStr.trim()));
            } catch (NumberFormatException e) {
                // 忽略非数字输入
            }
        }
        return sqlInjectionTestService.findUsersInListSafe(idList);
    }
    
    /**
     * 测试用例40：组合多种安全方式 - 安全实现
     */
    @GetMapping("/40")
    public List<User> testCase40(
            @RequestParam(required = false) Integer id,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String sortField) {
        
        // 白名单验证排序字段
        List<String> allowedFields = List.of("id", "username", "email");
        if (sortField != null && !allowedFields.contains(sortField)) {
            sortField = "id"; // 默认排序字段
        }
        
        // 安全方式查询
        List<User> users = sqlInjectionTestService.findUsersByMultipleConditionsSafe(id, username, email);
        
        // 如果需要排序，可以在应用层进行排序
        if (sortField != null) {
            if (sortField.equals("username")) {
                users.sort((a, b) -> a.getUsername().compareTo(b.getUsername()));
            } else if (sortField.equals("email")) {
                users.sort((a, b) -> {
                    if (a.getEmail() == null) return -1;
                    if (b.getEmail() == null) return 1;
                    return a.getEmail().compareTo(b.getEmail());
                });
            } else {
                users.sort((a, b) -> a.getId().compareTo(b.getId()));
            }
        }
        
        return users;
    }
    
    /**
     * 测试用例41：测试更新后的AOP切面 - 不安全实现
     */
    @GetMapping("/41")
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "使用更新后的@Before切面实现的不安全SQL查询",
            remediation = "使用参数化查询和参数绑定",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public List<Map<String, Object>> testCase41(@RequestParam String username) {
        return sqlInjectionTestService.testAspectUnsafeMethod(username);
    }
    
    /**
     * 测试用例42：测试更新后的AOP切面 - 安全实现
     */
    @GetMapping("/42")
    public List<Map<String, Object>> testCase42(@RequestParam String username) {
        return sqlInjectionTestService.testAspectSafeMethod(username);
    }
} 