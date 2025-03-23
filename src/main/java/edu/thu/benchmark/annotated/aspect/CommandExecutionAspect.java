package edu.thu.benchmark.annotated.aspect;

import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

/**
 * 命令执行切面
 * 提供命令执行的安全和不安全实现
 */
@Aspect
@Component
public class CommandExecutionAspect {

    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "echo", "cat");
    
    /**
     * 不安全的命令执行方法 - 直接执行用户提供的命令
     * @param command 要执行的命令
     * @return 命令执行结果
     */
    public String executeCommandUnsafe(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            return readProcessOutput(process);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * 安全的命令执行方法 - 验证命令并使用ProcessBuilder
     * @param command 要执行的命令
     * @return 命令执行结果
     */
    public String executeCommandSafe(String command) {
        try {
            String[] parts = command.split("\\s+", 2);
            
            // 验证命令是否在白名单中
            if (parts.length > 0 && ALLOWED_COMMANDS.contains(parts[0])) {
                // 验证参数不包含危险字符
                if (parts.length == 1 || !parts[1].matches(".*[;&|`\\\\\"'$].*")) {
                    ProcessBuilder processBuilder = new ProcessBuilder();
                    if (parts.length == 1) {
                        processBuilder.command(parts[0]);
                    } else {
                        processBuilder.command(parts[0], parts[1]);
                    }
                    Process process = processBuilder.start();
                    return readProcessOutput(process);
                }
            }
            
            return "Command not allowed";
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * 辅助方法：读取进程输出
     */
    private String readProcessOutput(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        }
    }
} 