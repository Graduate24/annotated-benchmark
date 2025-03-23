package edu.thu.benchmark.annotated.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * ZIP文件处理服务
 * 用于处理ZIP文件的解压和获取条目，包含不安全和安全的实现
 */
@Service
public class ZipService {

    @Value("${file.base.dir:/tmp/files}")
    private String baseDir;
    
    @Value("${zip.extract.dir:/tmp/extracts}")
    private String extractDir;

    /**
     * 不安全的ZIP条目获取实现
     * 从ZIP文件中获取条目但不验证路径
     *
     * @param zipFilePath ZIP文件路径
     * @param entryName 条目名称
     * @return 条目内容
     */
    public String getZipEntryUnsafe(String zipFilePath, String entryName) {
        try {
            // 不安全：直接使用用户提供的ZIP文件路径
            ZipFile zipFile = new ZipFile(new File(baseDir, zipFilePath));
            ZipEntry entry = zipFile.getEntry(entryName);
            
            if (entry == null) {
                return "Entry not found";
            }
            
            StringBuilder content = new StringBuilder();
            try (InputStream is = zipFile.getInputStream(entry)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = is.read(buffer)) > 0) {
                    content.append(new String(buffer, 0, len));
                }
            }
            
            zipFile.close();
            return content.toString();
        } catch (IOException e) {
            return "Error reading ZIP entry: " + e.getMessage();
        }
    }

    /**
     * 安全的ZIP条目获取实现
     * 验证ZIP条目路径不包含路径遍历模式
     *
     * @param zipFilePath ZIP文件路径
     * @param entryName 条目名称
     * @return 条目内容
     */
    public String getZipEntrySafe(String zipFilePath, String entryName) {
        try {
            // 安全：规范化路径并验证
            Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
            Path zipPath = basePath.resolve(zipFilePath).normalize();
            
            // 验证ZIP文件路径是否在预期目录内
            if (!zipPath.startsWith(basePath)) {
                throw new SecurityException("Access to the ZIP file is not allowed");
            }
            
            if (!Files.isRegularFile(zipPath)) {
                throw new IOException("ZIP file not found");
            }
            
            // 验证条目名称不包含路径遍历字符
            if (entryName.contains("..")) {
                throw new SecurityException("Invalid ZIP entry path");
            }
            
            ZipFile zipFile = new ZipFile(zipPath.toFile());
            ZipEntry entry = zipFile.getEntry(entryName);
            
            if (entry == null) {
                zipFile.close();
                return "Entry not found";
            }
            
            StringBuilder content = new StringBuilder();
            try (InputStream is = zipFile.getInputStream(entry)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = is.read(buffer)) > 0) {
                    content.append(new String(buffer, 0, len));
                }
            }
            
            zipFile.close();
            return content.toString();
        } catch (Exception e) {
            return "Error reading ZIP entry: " + e.getMessage();
        }
    }
    
    /**
     * 不安全的ZIP解压实现
     * 解压缩ZIP文件但不验证条目路径
     *
     * @param zipFilePath ZIP文件路径
     * @return 解压结果
     */
    public String extractZipUnsafe(String zipFilePath) {
        try {
            File zipFile = new File(baseDir, zipFilePath);
            if (!zipFile.exists()) {
                return "ZIP file not found";
            }
            
            ZipFile zip = new ZipFile(zipFile);
            
            // 创建解压目录
            File extractDirectory = new File(extractDir);
            if (!extractDirectory.exists()) {
                extractDirectory.mkdirs();
            }
            
            // 不安全：直接解压所有条目而不验证路径
            zip.stream().forEach(entry -> {
                try {
                    File entryFile = new File(extractDirectory, entry.getName());
                    
                    if (entry.isDirectory()) {
                        entryFile.mkdirs();
                    } else {
                        entryFile.getParentFile().mkdirs();
                        
                        try (InputStream is = zip.getInputStream(entry);
                             FileOutputStream fos = new FileOutputStream(entryFile)) {
                            byte[] buffer = new byte[1024];
                            int len;
                            while ((len = is.read(buffer)) > 0) {
                                fos.write(buffer, 0, len);
                            }
                        }
                    }
                } catch (IOException e) {
                    // 忽略单个条目的错误
                }
            });
            
            zip.close();
            return "ZIP file extracted successfully";
        } catch (IOException e) {
            return "Error extracting ZIP file: " + e.getMessage();
        }
    }
    
    /**
     * 安全的ZIP解压实现
     * 验证每个条目的路径不包含路径遍历模式
     *
     * @param zipFilePath ZIP文件路径
     * @return 解压结果
     */
    public String extractZipSafe(String zipFilePath) {
        try {
            // 安全：规范化路径并验证
            Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
            Path zipPath = basePath.resolve(zipFilePath).normalize();
            
            // 验证ZIP文件路径是否在预期目录内
            if (!zipPath.startsWith(basePath)) {
                throw new SecurityException("Access to the ZIP file is not allowed");
            }
            
            if (!Files.isRegularFile(zipPath)) {
                throw new IOException("ZIP file not found");
            }
            
            ZipFile zip = new ZipFile(zipPath.toFile());
            
            // 创建解压目录
            Path extractDirPath = Paths.get(extractDir).toAbsolutePath().normalize();
            if (!Files.exists(extractDirPath)) {
                Files.createDirectories(extractDirPath);
            }
            
            // 安全：验证每个条目的路径不包含路径遍历模式
            zip.stream().forEach(entry -> {
                try {
                    // 关键安全措施：规范化并验证条目路径
                    Path entryPath = extractDirPath.resolve(entry.getName()).normalize();
                    
                    // 验证最终路径是否在解压目录内
                    if (!entryPath.startsWith(extractDirPath)) {
                        throw new SecurityException("ZIP entry is outside of the target directory: " + entry.getName());
                    }
                    
                    if (entry.isDirectory()) {
                        Files.createDirectories(entryPath);
                    } else {
                        Files.createDirectories(entryPath.getParent());
                        
                        try (InputStream is = zip.getInputStream(entry)) {
                            Files.copy(is, entryPath);
                        }
                    }
                } catch (Exception e) {
                    // 记录错误但继续处理其他条目
                    System.err.println("Error extracting entry " + entry.getName() + ": " + e.getMessage());
                }
            });
            
            zip.close();
            return "ZIP file extracted successfully";
        } catch (Exception e) {
            return "Error extracting ZIP file: " + e.getMessage();
        }
    }
} 