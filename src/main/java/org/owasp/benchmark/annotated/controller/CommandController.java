package org.owasp.benchmark.annotated.controller;

import org.owasp.benchmark.annotated.annotation.Vulnerability;
import org.owasp.benchmark.annotated.annotation.VulnerabilityLevel;
import org.owasp.benchmark.annotated.annotation.VulnerabilityType;
import org.owasp.benchmark.annotated.entity.CommandExecution;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * 命令执行控制器
 * 包含命令注入漏洞示例
 */
@Controller
@RequestMapping("/command")
public class CommandController {

    @Value("${app.command.executor}")
    private String commandExecutor;

    /**
     * 显示命令执行页面
     */
    @GetMapping
    public String showCommandPage() {
        return "command/execute";
    }

    /**
     * 执行命令 - 不安全方式（直接执行用户输入的命令）
     * 存在命令注入漏洞
     */
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.COMMAND_INJECTION,
            description = "直接执行用户输入的命令，没有任何过滤或验证",
            remediation = "使用白名单验证允许的命令，避免直接拼接用户输入到命令中",
            level = VulnerabilityLevel.CRITICAL
    )
    @PostMapping("/execute")
    @ResponseBody
    public String executeCommand(@RequestParam String command) {
        StringBuilder output = new StringBuilder();
        CommandExecution execution = new CommandExecution(command, "admin");
        
        try {
            // 直接执行用户输入的命令，存在命令注入漏洞
            Process process = Runtime.getRuntime().exec(command);
            
            // 记录命令执行结果
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // 等待命令执行完成
            boolean completed = process.waitFor(10, TimeUnit.SECONDS);
            
            if (completed) {
                execution.setStatus("成功");
                execution.setOutput(output.toString());
                return "命令执行成功:\n" + output.toString();
            } else {
                process.destroyForcibly();
                execution.setStatus("超时");
                return "命令执行超时";
            }
        } catch (IOException | InterruptedException e) {
            execution.setStatus("失败");
            execution.setOutput(e.getMessage());
            return "命令执行失败: " + e.getMessage();
        }
    }

    /**
     * 执行预定义命令 - 不安全方式（通过用户输入参数拼接命令）
     * 存在命令注入漏洞
     */
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.COMMAND_INJECTION,
            description = "将用户输入直接拼接到命令中，可以通过特殊字符注入其他命令",
            remediation = "避免将用户输入直接拼接到命令中，使用参数化方式传递参数",
            level = VulnerabilityLevel.HIGH
    )
    @GetMapping("/ping")
    @ResponseBody
    public String pingHost(@RequestParam String host) {
        StringBuilder output = new StringBuilder();
        String command = "ping -c 4 " + host;  // 不安全：直接拼接用户输入
        
        try {
            // 直接执行拼接后的命令，存在命令注入漏洞
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor(5, TimeUnit.SECONDS);
            return output.toString();
        } catch (IOException | InterruptedException e) {
            return "执行ping命令失败: " + e.getMessage();
        }
    }

    /**
     * 执行系统命令 - 使用预定义的命令执行器（仍存在风险）
     */
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.COMMAND_INJECTION,
            description = "通过配置文件定义的命令执行器执行命令，可能存在配置不当导致的注入",
            remediation = "使用安全的API代替命令执行，如果必须执行命令，确保严格校验和限制",
            level = VulnerabilityLevel.MEDIUM
    )
    @GetMapping("/system")
    @ResponseBody
    public String executeSystemCommand(@RequestParam String args) {
        StringBuilder output = new StringBuilder();
        String command = commandExecutor + " " + args;  // 使用配置的执行器，但仍拼接用户输入
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor(5, TimeUnit.SECONDS);
            return output.toString();
        } catch (IOException | InterruptedException e) {
            return "执行系统命令失败: " + e.getMessage();
        }
    }
}