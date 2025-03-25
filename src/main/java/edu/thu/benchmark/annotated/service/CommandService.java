package edu.thu.benchmark.annotated.service;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 命令执行服务
 * 演示如何在服务类中使用@Value注解获取命令执行器配置
 */
@Service
public class CommandService {

    // 直接从配置文件中获取命令执行器
    // 原注解: @Value("${app.command.executor}")
    private String commandExecutor = "/bin/bash";

    // 允许执行的命令白名单
    // 原注解: @Value("${app.command.whitelist}")
    private String commandWhitelist = "ls,dir,pwd,whoami,date,echo";

    // 参数验证的正则表达式
    // 原注解: @Value("${app.command.arg-pattern}")
    private String argPattern = "[a-zA-Z0-9_\\-\\.]*";

    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "echo", "cat");

    /**
     * 不安全的命令执行方法
     * 直接拼接用户输入作为命令参数
     */
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.COMMAND_INJECTION,
            description = "直接拼接用户输入作为命令参数，未进行验证",
            remediation = "验证命令和参数，使用参数数组而非字符串拼接",
            level = VulnerabilityLevel.CRITICAL
    )
    public String executeCommandUnsafe(String command) throws IOException {
        // 不安全：直接使用用户输入的命令
        Process process = Runtime.getRuntime().exec(commandExecutor + " -c \"" + command + "\"");

        // 读取命令输出
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }

        return output.toString();
    }

    /**
     * 安全的命令执行方法
     * 验证命令和参数，使用参数数组
     */
    public String executeCommandSafe(String command) throws IOException {
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

    /**
     * 获取命令执行器
     */
    public String getCommandExecutor() {
        return commandExecutor;
    }

    /**
     * 获取命令白名单
     */
    public String getCommandWhitelist() {
        return commandWhitelist;
    }
}
