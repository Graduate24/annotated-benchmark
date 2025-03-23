package edu.thu.benchmark.annotated.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * 模板服务类
 * 用于获取模板文件内容，包含不安全和安全的实现
 */
@Service
public class TemplateService {

    @Value("${template.dir}")
    private String templateDir;

    // 安全白名单模式，只允许字母、数字、下划线和连字符以及.html扩展名
    private static final Pattern SAFE_TEMPLATE_PATTERN = Pattern.compile("[a-zA-Z0-9_-]+\\.html");

    /**
     * 不安全的模板获取实现
     * 直接使用用户提供的模板名而不验证
     *
     * @param templateName 模板名称
     * @return 模板内容
     */
    public String getTemplateUnsafe(String templateName) {
        try {
            // 不安全：直接拼接模板路径而不验证
            File templateFile = new File(templateDir, templateName);
            return new String(Files.readAllBytes(templateFile.toPath()));
        } catch (IOException e) {
            return "Error loading template: " + e.getMessage();
        }
    }

    /**
     * 安全的模板获取实现
     * 验证模板名称并确保访问路径在预期目录内
     *
     * @param templateName 模板名称
     * @return 模板内容
     */
    public String getTemplateSafe(String templateName) {
        // 安全：白名单验证模板名称
        if (!SAFE_TEMPLATE_PATTERN.matcher(templateName).matches()) {
            throw new SecurityException("Invalid template name");
        }

        try {
            Path basePath = Paths.get(templateDir).toAbsolutePath().normalize();
            Path templatePath = basePath.resolve(templateName).normalize();

            // 验证模板路径是否在预期目录内
            if (!templatePath.startsWith(basePath)) {
                throw new SecurityException("Access to the template is not allowed");
            }

            if (!Files.isRegularFile(templatePath)) {
                throw new IOException("Template not found");
            }

            return new String(Files.readAllBytes(templatePath));
        } catch (IOException e) {
            return "Error loading template: " + e.getMessage();
        }
    }

    /**
     * 不安全的多级模板获取实现
     * 允许用户指定子目录路径
     *
     * @param templatePath 模板路径
     * @return 模板内容
     */
    public String getNestedTemplateUnsafe(String templatePath) {
        try {
            // 不安全：直接拼接模板路径而不验证，允许用户指定子目录
            File templateFile = new File(templateDir, templatePath);
            return new String(Files.readAllBytes(templateFile.toPath()));
        } catch (IOException e) {
            return "Error loading template: " + e.getMessage();
        }
    }

    /**
     * 安全的多级模板获取实现
     * 验证模板路径不包含路径遍历字符
     *
     * @param templatePath 模板路径
     * @return 模板内容
     */
    public String getNestedTemplateSafe(String templatePath) {
        // 安全：验证不包含路径遍历字符
        if (templatePath.contains("..")) {
            throw new SecurityException("Invalid template path");
        }

        try {
            Path basePath = Paths.get(templateDir).toAbsolutePath().normalize();
            Path templateFullPath = basePath.resolve(templatePath).normalize();

            // 验证模板路径是否在预期目录内
            if (!templateFullPath.startsWith(basePath)) {
                throw new SecurityException("Access to the template is not allowed");
            }

            if (!Files.isRegularFile(templateFullPath)) {
                throw new IOException("Template not found");
            }

            return new String(Files.readAllBytes(templateFullPath));
        } catch (IOException e) {
            return "Error loading template: " + e.getMessage();
        }
    }
}
