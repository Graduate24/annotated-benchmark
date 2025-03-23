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
import java.util.List;
import java.util.regex.Pattern;

/**
 * 命令执行服务
 * 演示如何在服务类中使用@Value注解获取命令执行器配置
 */
@Service
public class CommandService {

    // 直接从配置文件中获取命令执行器
    @Value("${app.command.executor}")
    private String commandExecutor;

    // 允许执行的命令白名单
    @Value("${app.command.whitelist:ls,dir,pwd,whoami,date,echo}")
    private String commandWhitelist;

    // 参数验证的正则表达式
    @Value("${app.command.arg-pattern:[a-zA-Z0-9_\\-\\.]*}")
    private String argPattern;

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
    public String executeCommandSafe(String command, String... args) throws IOException {
        // 验证命令是否在白名单中
        if (!isCommandAllowed(command)) {
            throw new IllegalArgumentException("不允许执行该命令: " + command);
        }

        // 验证参数
        for (String arg : args) {
            if (!isArgumentSafe(arg)) {
                throw new IllegalArgumentException("参数包含不允许的字符: " + arg);
            }
        }

        // 构建命令数组
        List<String> commandArray = new ArrayList<>();
        commandArray.add(commandExecutor);
        commandArray.add("-c");

        // 构建完整命令字符串，但使用数组传入避免shell注入
        StringBuilder commandStr = new StringBuilder(command);
        for (String arg : args) {
            commandStr.append(" ").append(arg);
        }
        commandArray.add(commandStr.toString());

        // 执行命令
        ProcessBuilder processBuilder = new ProcessBuilder(commandArray);
        Process process = processBuilder.start();

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
     * 检查命令是否在白名单中
     */
    private boolean isCommandAllowed(String command) {
        String[] allowedCommands = commandWhitelist.split(",");
        for (String allowedCommand : allowedCommands) {
            if (command.equals(allowedCommand.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查参数是否安全
     */
    private boolean isArgumentSafe(String arg) {
        return Pattern.matches(argPattern, arg);
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
