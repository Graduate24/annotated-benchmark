package edu.thu.benchmark.annotated.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * 应用配置类
 * 演示如何使用@Value注解从配置文件中获取配置项
 */
@Configuration
@Component
public class AppConfig {

    // 应用基本配置
    @Value("${spring.application.name}")
    private String applicationName;

    @Value("${server.port}")
    private int serverPort;

    // 数据源配置
    @Value("${spring.datasource.url}")
    private String datasourceUrl;

    @Value("${spring.datasource.username}")
    private String datasourceUsername;

    @Value("${spring.datasource.password}")
    private String datasourcePassword;

    // 自定义属性
    @Value("${app.upload.directory}")
    private String uploadDirectory;

    @Value("${app.command.executor}")
    private String commandExecutor;

    @Value("${app.database.query.template}")
    private String queryTemplate;

    @Value("${app.security.enabled}")
    private boolean securityEnabled;

    // 可以设置默认值的配置项
    @Value("${app.timeout}")
    private int timeout;

    @Value("${app.max-connections}")
    private int maxConnections;

    // 获取系统属性
    @Value("${user.home}")
    private String userHome;

    /**
     * 获取应用名称
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * 获取服务器端口
     */
    public int getServerPort() {
        return serverPort;
    }

    /**
     * 获取数据源URL
     */
    public String getDatasourceUrl() {
        return datasourceUrl;
    }

    /**
     * 获取数据源用户名
     */
    public String getDatasourceUsername() {
        return datasourceUsername;
    }

    /**
     * 获取数据源密码
     */
    public String getDatasourcePassword() {
        return datasourcePassword;
    }

    /**
     * 获取上传目录
     */
    public String getUploadDirectory() {
        return uploadDirectory;
    }

    /**
     * 获取命令执行器
     */
    public String getCommandExecutor() {
        return commandExecutor;
    }

    /**
     * 获取查询模板
     */
    public String getQueryTemplate() {
        return queryTemplate;
    }

    /**
     * 检查安全是否启用
     */
    public boolean isSecurityEnabled() {
        return securityEnabled;
    }

    /**
     * 获取超时时间
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * 获取最大连接数
     */
    public int getMaxConnections() {
        return maxConnections;
    }

    /**
     * 获取用户主目录
     */
    public String getUserHome() {
        return userHome;
    }
}
