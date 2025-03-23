package edu.thu.benchmark.annotated.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * 文件工具类
 * 包含文件操作的不安全实现和安全实现
 */
public class FileUtils {

    /**
     * 不安全的文件读取实现
     * 直接使用无验证的路径读取文件
     *
     * @param basePath 基础路径
     * @param filePath 文件路径
     * @return 文件内容
     */
    public static String readFileUnsafe(String basePath, String filePath) {
        try {
            // 不安全：直接拼接路径而不验证
            File file = new File(basePath, filePath);
            byte[] content = new byte[(int) file.length()];
            try (FileInputStream fis = new FileInputStream(file)) {
                fis.read(content);
            }
            return new String(content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    /**
     * 安全的文件读取实现
     * 规范化路径并验证路径安全性
     *
     * @param basePath 基础路径
     * @param filePath 文件路径
     * @return 文件内容
     */
    public static String readFileSafe(String basePath, String filePath) {
        try {
            // 安全：规范化路径并验证
            Path base = Paths.get(basePath).toAbsolutePath().normalize();
            Path resolved = base.resolve(filePath).normalize();
            
            // 验证最终路径是否在基础目录内
            if (!resolved.startsWith(base)) {
                throw new SecurityException("Access to the file is not allowed");
            }
            
            if (!Files.isRegularFile(resolved)) {
                throw new IOException("File not found or not a regular file");
            }
            
            return new String(Files.readAllBytes(resolved), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }
    
    /**
     * 不安全的目录内容列表实现
     * 直接使用无验证的路径列出目录内容
     *
     * @param basePath 基础路径
     * @param dirPath 目录路径
     * @return 目录内容列表
     */
    public static List<String> listDirectoryUnsafe(String basePath, String dirPath) {
        List<String> result = new ArrayList<>();
        try {
            // 不安全：直接拼接路径而不验证
            File dir = new File(basePath, dirPath);
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    result.add(file.getName());
                }
            }
        } catch (Exception e) {
            result.add("Error listing directory: " + e.getMessage());
        }
        return result;
    }
    
    /**
     * 安全的目录内容列表实现
     * 规范化路径并验证路径安全性
     *
     * @param basePath 基础路径
     * @param dirPath 目录路径
     * @return 目录内容列表
     */
    public static List<String> listDirectorySafe(String basePath, String dirPath) {
        List<String> result = new ArrayList<>();
        try {
            // 安全：规范化路径并验证
            Path base = Paths.get(basePath).toAbsolutePath().normalize();
            Path resolved = base.resolve(dirPath).normalize();
            
            // 验证最终路径是否在基础目录内
            if (!resolved.startsWith(base)) {
                throw new SecurityException("Access to the directory is not allowed");
            }
            
            if (!Files.isDirectory(resolved)) {
                throw new IOException("Directory not found");
            }
            
            Files.list(resolved).forEach(path -> {
                result.add(path.getFileName().toString());
            });
        } catch (Exception e) {
            result.add("Error listing directory: " + e.getMessage());
        }
        return result;
    }
    
    /**
     * 不安全的文件路径拼接实现
     * 直接拼接路径而不验证
     *
     * @param basePath 基础路径
     * @param relativePath 相对路径
     * @return 拼接后的路径
     */
    public static String joinPathsUnsafe(String basePath, String relativePath) {
        // 不安全：直接拼接路径而不验证
        return basePath + File.separator + relativePath;
    }
    
    /**
     * 安全的文件路径拼接实现
     * 规范化路径并验证路径安全性
     *
     * @param basePath 基础路径
     * @param relativePath 相对路径
     * @return 拼接后的路径
     */
    public static String joinPathsSafe(String basePath, String relativePath) {
        try {
            // 安全：规范化路径并验证
            Path base = Paths.get(basePath).toAbsolutePath().normalize();
            Path resolved = base.resolve(relativePath).normalize();
            
            // 验证最终路径是否在基础目录内
            if (!resolved.startsWith(base)) {
                throw new SecurityException("Resulting path is outside the base directory");
            }
            
            return resolved.toString();
        } catch (Exception e) {
            return null; // 返回null表示路径不安全
        }
    }
} 