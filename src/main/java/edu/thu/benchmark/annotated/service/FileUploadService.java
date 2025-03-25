package edu.thu.benchmark.annotated.service;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * 文件上传服务
 * 演示如何在服务类中使用@Value注解获取配置项
 */
@Service
public class FileUploadService {

    // 原注解: @Value("${app.upload.directory}")
    private String uploadDirectory = "./uploads";

    // 原注解: @Value("${app.upload.max-size}") // 默认10MB
    private long maxFileSize = 10485760;

    // 原注解: @Value("${app.upload.allowed-extensions}")
    private String allowedExtensions = ".jpg,.jpeg,.png,.pdf,.docx";

    /**
     * 不安全的文件上传方法
     * 直接使用用户提供的文件名
     */
    @Vulnerability(
            cwe = 434,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "不安全的文件上传，使用用户提供的文件名，未进行验证",
            remediation = "验证文件名并使用安全的文件名生成方式",
            level = VulnerabilityLevel.HIGH
    )
    public String saveFileUnsafe(MultipartFile file, String customName) throws IOException {
        // 创建目录（如果不存在）
        File directory = new File(uploadDirectory);
        if (!directory.exists()) {
            directory.mkdirs();
        }

        // 不安全：直接使用用户提供的自定义名称
        String fileName = customName != null ? customName : file.getOriginalFilename();
        Path filePath = Paths.get(uploadDirectory, fileName);

        // 保存文件
        Files.write(filePath, file.getBytes());

        return filePath.toString();
    }

    /**
     * 安全的文件上传方法
     * 使用随机生成的文件名
     */
    public String saveFileSafe(MultipartFile file) throws IOException {
        // 验证文件大小
        if (file.getSize() > maxFileSize) {
            throw new IllegalArgumentException("文件大小超过限制");
        }

        // 验证文件类型
        String originalFilename = file.getOriginalFilename();
        if (!isAllowedFileType(originalFilename)) {
            throw new IllegalArgumentException("不支持的文件类型");
        }

        // 创建目录（如果不存在）
        File directory = new File(uploadDirectory);
        if (!directory.exists()) {
            directory.mkdirs();
        }

        // 生成安全的随机文件名，但保留原始扩展名
        String extension = "";
        if (originalFilename != null && originalFilename.contains(".")) {
            extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        }
        String safeFileName = UUID.randomUUID().toString() + extension;

        // 保存文件
        Path filePath = Paths.get(uploadDirectory, safeFileName);
        Files.write(filePath, file.getBytes());

        return filePath.toString();
    }

    /**
     * 检查文件类型是否允许
     */
    private boolean isAllowedFileType(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return false;
        }

        String extension = fileName.substring(fileName.lastIndexOf(".")).toLowerCase();
        String[] allowedExtensionArray = allowedExtensions.split(",");

        for (String allowedExt : allowedExtensionArray) {
            if (extension.equals(allowedExt.trim())) {
                return true;
            }
        }

        return false;
    }

    /**
     * 获取上传目录
     */
    public String getUploadDirectory() {
        return uploadDirectory;
    }

    /**
     * 获取最大文件大小
     */
    public long getMaxFileSize() {
        return maxFileSize;
    }

    /**
     * 获取允许的文件扩展名
     */
    public String getAllowedExtensions() {
        return allowedExtensions;
    }
}
