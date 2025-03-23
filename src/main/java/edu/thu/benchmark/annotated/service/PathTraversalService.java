package edu.thu.benchmark.annotated.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 路径遍历Service
 * 包含文件访问的不安全实现和安全实现
 */
@Service
public class PathTraversalService {

    @Value("${file.base.dir:/tmp/files}")
    private String baseDir;

    /**
     * 不安全的文件读取实现
     * 直接使用用户提供的路径而不验证
     *
     * @param filePath 用户提供的文件路径
     * @return 文件内容
     */
    public String readFileUnsafe(String filePath) {
        StringBuilder content = new StringBuilder();
        try {
            // 不安全：直接使用用户提供的路径
            File file = new File(baseDir, filePath);
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\n");
                }
            }
        } catch (IOException e) {
            content.append("Error reading file: ").append(e.getMessage());
        }
        return content.toString();
    }

    /**
     * 安全的文件读取实现
     * 对输入路径进行规范化和验证
     *
     * @param filePath 用户提供的文件路径
     * @return 文件内容
     */
    public String readFileSafe(String filePath) {
        StringBuilder content = new StringBuilder();
        try {
            // 安全：规范化路径并验证
            Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
            Path resolvedPath = basePath.resolve(filePath).normalize();
            
            // 验证最终路径是否在允许的目录内
            if (!resolvedPath.startsWith(basePath)) {
                throw new SecurityException("Access to the file is not allowed");
            }
            
            if (!Files.isRegularFile(resolvedPath)) {
                throw new IOException("File not found or not a regular file");
            }
            
            content.append(new String(Files.readAllBytes(resolvedPath)));
        } catch (Exception e) {
            content.append("Error reading file: ").append(e.getMessage());
        }
        return content.toString();
    }
    
    /**
     * 不安全的目录列表实现
     * 未验证用户提供的目录路径
     *
     * @param dirPath 用户提供的目录路径
     * @return 目录内容列表
     */
    public String[] listFilesUnsafe(String dirPath) {
        // 不安全：直接拼接用户提供的目录路径
        File dir = new File(baseDir + "/" + dirPath);
        return dir.list();
    }
    
    /**
     * 安全的目录列表实现
     * 验证用户提供的目录路径
     *
     * @param dirPath 用户提供的目录路径
     * @return 目录内容列表
     */
    public String[] listFilesSafe(String dirPath) {
        try {
            // 安全：规范化路径并验证
            Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
            Path resolvedPath = basePath.resolve(dirPath).normalize();
            
            // 验证最终路径是否在允许的目录内
            if (!resolvedPath.startsWith(basePath)) {
                throw new SecurityException("Access to the directory is not allowed");
            }
            
            if (!Files.isDirectory(resolvedPath)) {
                throw new IOException("Directory not found");
            }
            
            return Files.list(resolvedPath)
                    .map(path -> path.getFileName().toString())
                    .toArray(String[]::new);
        } catch (Exception e) {
            return new String[]{"Error listing directory: " + e.getMessage()};
        }
    }
} 