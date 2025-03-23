package edu.thu.benchmark.annotated.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 文件访问切面
 * 用于拦截和记录文件访问操作
 */
@Aspect
@Component
public class FileAccessAspect {

    @Value("${log.dir:/tmp/logs}")
    private String logDir;
    
    /**
     * 不安全的日志文件访问实现
     * 在切面中直接使用用户提供的路径获取文件
     *
     * @param logFile 日志文件名
     * @return 日志文件内容
     */
    public String accessLogFile(String logFile) {
        try {
            // 不安全：直接使用用户提供的日志文件路径
            File file = new File(logFile);
            return new String(Files.readAllBytes(file.toPath()));
        } catch (IOException e) {
            return "Error accessing log file: " + e.getMessage();
        }
    }
    
    /**
     * 安全的日志文件访问实现
     * 在切面中实现完整的路径验证逻辑
     *
     * @param logFile 日志文件名
     * @return 日志文件内容
     */
    public String accessLogFileSafe(String logFile) {
        try {
            // 安全：规范化路径并验证
            Path basePath = Paths.get(logDir).toAbsolutePath().normalize();
            Path logPath = basePath.resolve(logFile).normalize();
            
            // 验证最终路径是否在日志目录内
            if (!logPath.startsWith(basePath)) {
                throw new SecurityException("Access to the log file is not allowed");
            }
            
            if (!Files.isRegularFile(logPath)) {
                throw new IOException("Log file not found or not a regular file");
            }
            
            return new String(Files.readAllBytes(logPath));
        } catch (Exception e) {
            return "Error accessing log file: " + e.getMessage();
        }
    }
    
    /**
     * 记录不安全的文件访问操作
     * 直接记录用户提供的路径而不验证
     */
    @Before("execution(* edu.thu.benchmark.annotated.controller.PathTraversalController.getFile*(..))")
    public void logFileAccessUnsafe(JoinPoint joinPoint) {
        try {
            // 获取方法参数（文件路径）
            Object[] args = joinPoint.getArgs();
            if (args.length > 0 && args[0] instanceof String) {
                String filePath = (String) args[0];
                // 不安全：直接使用用户提供的路径构造日志文件路径
                File logFile = new File(logDir, "file_access.log");
                Files.write(logFile.toPath(), 
                        ("Accessed file: " + filePath + "\n").getBytes(), 
                        java.nio.file.StandardOpenOption.CREATE, 
                        java.nio.file.StandardOpenOption.APPEND);
            }
        } catch (IOException e) {
            // 记录错误但不中断执行
            System.err.println("Error logging file access: " + e.getMessage());
        }
    }
    
    /**
     * 记录安全的文件访问操作
     * 对用户提供的路径进行规范化和验证
     */
    @Before("execution(* edu.thu.benchmark.annotated.controller.PathTraversalController.getFile*Safe*(..))")
    public void logFileAccessSafe(JoinPoint joinPoint) {
        try {
            // 获取方法参数（文件路径）
            Object[] args = joinPoint.getArgs();
            if (args.length > 0 && args[0] instanceof String) {
                String filePath = (String) args[0];
                
                // 安全：规范化并验证路径
                String sanitizedPath = filePath.replaceAll("[^a-zA-Z0-9_.-]", "_");
                
                // 构造安全的日志文件路径
                Path logFilePath = Paths.get(logDir, "file_access_safe.log").normalize();
                
                // 确保日志目录存在
                Files.createDirectories(logFilePath.getParent());
                
                // 记录访问信息
                Files.write(logFilePath, 
                        ("Safely accessed file: " + sanitizedPath + "\n").getBytes(), 
                        java.nio.file.StandardOpenOption.CREATE, 
                        java.nio.file.StandardOpenOption.APPEND);
            }
        } catch (IOException e) {
            // 记录错误但不中断执行
            System.err.println("Error safely logging file access: " + e.getMessage());
        }
    }
    
    /**
     * 不安全的文件操作前置通知
     * 在特定操作前进行文件处理但不验证路径
     */
    @Before("execution(* edu.thu.benchmark.annotated.controller.PathTraversalController.getFileWithAspect*(..))")
    public void beforeUnsafeFileAccess(JoinPoint joinPoint) {
        try {
            // 获取方法参数（文件路径）
            Object[] args = joinPoint.getArgs();
            if (args.length > 0 && args[0] instanceof String) {
                String filePath = (String) args[0];
                // 不安全：直接使用用户提供的路径
                File file = new File(filePath);
                if (file.exists()) {
                    // 在访问前执行某些操作，但不验证路径安全性
                    System.out.println("About to access file: " + file.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            System.err.println("Error in file access aspect: " + e.getMessage());
        }
    }
    
    /**
     * 安全的文件操作前置通知
     * 在特定操作前进行文件处理并验证路径
     */
    @Before("execution(* edu.thu.benchmark.annotated.controller.PathTraversalController.getFileWithAspectSafe*(..))")
    public void beforeSafeFileAccess(JoinPoint joinPoint) {
        try {
            // 获取方法参数（文件路径）
            Object[] args = joinPoint.getArgs();
            if (args.length > 0 && args[0] instanceof String) {
                String filePath = (String) args[0];
                
                // 安全：规范化路径并验证
                Path basePath = Paths.get(logDir).toAbsolutePath().normalize();
                Path resolvedPath = basePath.resolve(filePath).normalize();
                
                // 验证最终路径是否在允许的目录内
                if (resolvedPath.startsWith(basePath) && Files.exists(resolvedPath)) {
                    // 在访问前执行某些操作，并验证路径安全性
                    System.out.println("About to safely access file: " + resolvedPath);
                } else {
                    throw new SecurityException("Access to the file is not allowed or file does not exist");
                }
            }
        } catch (Exception e) {
            System.err.println("Error in safe file access aspect: " + e.getMessage());
        }
    }
} 