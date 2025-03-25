package edu.thu.benchmark.annotated.controller;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import edu.thu.benchmark.annotated.aspect.CommandExecutionAspect;
import edu.thu.benchmark.annotated.service.CommandService;
import edu.thu.benchmark.annotated.util.CommandUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 命令注入测试控制器
 * 包含20个测试用例，10个正例（存在漏洞）和10个负例（安全实现）
 */
@RestController
@RequestMapping("/command")
public class CommandInjectionController {

    // 原注解: @Value("${command.allowed.prefix}")
    private String allowedCommandPrefix = "ls,cat,echo,pwd,grep,find";

    // 原注解: @Autowired
    private CommandService commandService = new CommandService();

    // 原注解: @Autowired
    private CommandExecutionAspect commandExecutionAspect = new CommandExecutionAspect();

    // ======== 测试用例 - 正例（存在命令注入漏洞） ========

    /**
     * 测试用例1：直接拼接命令 - 不安全实现
     */
    @GetMapping("/01")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "直接拼接用户输入到命令字符串中",
            remediation = "使用ProcessBuilder并单独指定每个参数，避免使用shell解释器",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String executeCommand01(@RequestParam String command) throws IOException {
        Process process = Runtime.getRuntime().exec("ls " + command); // 不安全：直接拼接命令
        return readProcessOutput(process);
    }

    /**
     * 测试用例2：使用系统属性构建命令 - 不安全实现
     */
    @GetMapping("/02")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "将用户输入与系统属性拼接形成命令",
            remediation = "使用命令白名单或使用ProcessBuilder避免shell注入",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String executeWithSystemProperty02(@RequestParam String path) throws IOException {
        String userDir = System.getProperty("user.dir");
        Process process = Runtime.getRuntime().exec("cd " + userDir + " && ls " + path); // 不安全：拼接多个命令
        return readProcessOutput(process);
    }

    /**
     * 测试用例3：使用Runtime.exec数组形式但仍有注入点 - 不安全实现
     */
    @GetMapping("/03")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "虽然使用数组方式，但命令中包含shell特殊字符",
            remediation = "避免在命令参数中包含shell解释的特殊字符",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String executeArrayWithInjection03(@RequestParam String file) throws IOException {
        // 不安全：file参数可能包含 && 或 ; 等命令连接符
        String[] command = new String[]{"/bin/sh", "-c", "cat " + file};
        Process process = Runtime.getRuntime().exec(command);
        return readProcessOutput(process);
    }

    /**
     * 测试用例4：通过依赖注入的Service执行命令 - 不安全实现
     */
    @GetMapping("/04")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "通过依赖注入的Service执行未经验证的命令",
            remediation = "在Service层实现命令验证逻辑",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String executeViaService04(@RequestParam String command) throws IOException {
        return commandService.executeCommandUnsafe(command); // 不安全：在Service中未验证命令
    }

    /**
     * 测试用例5：通过AOP切面执行命令 - 不安全实现
     */
    @GetMapping("/05")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "通过AOP切面执行未经验证的命令",
            remediation = "在AOP切面中实现命令验证逻辑",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String executeViaAspect05(@RequestParam String command) {
        // 不安全：通过切面执行的命令但切面中未验证命令
        return commandExecutionAspect.executeCommandUnsafe(command);
    }

    /**
     * 测试用例6：使用ProcessBuilder但仍拼接命令 - 不安全实现
     */
    @GetMapping("/06")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "使用ProcessBuilder但仍将用户输入拼接到命令中",
            remediation = "使用ProcessBuilder的command方法分别添加每个参数",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String executeWithProcessBuilder06(@RequestParam String arg) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder("ls", "-la " + arg); // 不安全：参数中包含拼接
        Process process = processBuilder.start();
        return readProcessOutput(process);
    }

    /**
     * 测试用例7：从配置文件读取命令前缀 - 不安全实现
     */
    @GetMapping("/07")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "从配置中读取命令前缀后仍将用户输入直接拼接",
            remediation = "使用白名单验证完整命令，不仅仅是前缀",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String executeWithConfigPrefix07(@RequestParam String command) throws IOException {
        // 不安全：仅验证前缀但不限制后续参数
        String[] allowedPrefixes = allowedCommandPrefix.split(",");
        String[] parts = command.split("\\s+", 2);

        if (parts.length > 0 && Arrays.asList(allowedPrefixes).contains(parts[0])) {
            Process process = Runtime.getRuntime().exec(command); // 不安全：用户仍可添加 && 或 ; 等连接其他命令
            return readProcessOutput(process);
        }

        return "Command not allowed";
    }

    /**
     * 测试用例8：使用工具类执行命令 - 不安全实现
     */
    @GetMapping("/08")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "通过工具类执行未经验证的命令",
            remediation = "在工具类中实现命令验证逻辑",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String executeViaUtils08(@RequestParam String command) {
        return CommandUtils.executeUnsafe(command); // 不安全：在工具类中未验证命令
    }

    /**
     * 测试用例9：传入多个参数构建命令 - 不安全实现
     */
    @GetMapping("/09")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "使用多个用户参数构建命令字符串",
            remediation = "使用ProcessBuilder并对每个参数单独验证",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String executeWithMultipleParams09(@RequestParam String dir, @RequestParam String filter) throws IOException {
        // 不安全：多个参数拼接，用户可在任一参数中包含命令连接符
        String command = "cd " + dir + " && ls " + filter;
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        return readProcessOutput(process);
    }

    /**
     * 测试用例10：使用命令执行文件操作 - 不安全实现
     */
    @GetMapping("/10")
    @Vulnerability(
            cwe = 78,
            type = VulnerabilityType.OS_COMMAND_INJECTION,
            description = "使用命令执行文件操作而不是使用API",
            remediation = "使用Java文件API代替命令行执行文件操作",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String fileOperationWithCommand10(@RequestParam String fileName) throws IOException {
        // 不安全：使用命令行执行文件操作，fileName可能包含恶意命令
        Process process = Runtime.getRuntime().exec("cat " + fileName);
        return readProcessOutput(process);
    }

    // ======== 测试用例 - 负例（安全实现） ========

    /**
     * 测试用例11：使用ProcessBuilder安全执行命令
     */
    @GetMapping("/11")
    public String executeCommandSafe01(@RequestParam String fileName) throws IOException {
        // 安全：使用ProcessBuilder并分别指定每个参数
        ProcessBuilder processBuilder = new ProcessBuilder("ls", fileName);
        Process process = processBuilder.start();
        return readProcessOutput(process);
    }

    /**
     * 测试用例12：使用命令白名单
     */
    @GetMapping("/12")
    public String executeWithWhitelistSafe02(@RequestParam String command) throws IOException {
        // 安全：使用白名单限制可执行的命令
        List<String> allowedCommands = Arrays.asList("ls -l", "ls -la", "echo hello", "date");

        if (allowedCommands.contains(command)) {
            Process process = Runtime.getRuntime().exec(command);
            return readProcessOutput(process);
        }

        return "Command not allowed";
    }

    /**
     * 测试用例13：安全使用Runtime.exec数组形式
     */
    @GetMapping("/13")
    public String executeArraySafe03(@RequestParam String file) throws IOException {
        // 安全：使用数组形式并分别指定每个参数，不使用shell
        String[] command = new String[]{"cat", file};
        Process process = Runtime.getRuntime().exec(command);
        return readProcessOutput(process);
    }

    /**
     * 测试用例14：通过依赖注入的Service安全执行命令
     */
    @GetMapping("/14")
    public String executeViaServiceSafe04(@RequestParam String command) throws IOException {
        return commandService.executeCommandSafe(command); // 安全：在Service中验证命令
    }

    /**
     * 测试用例15：通过AOP切面安全执行命令
     */
    @GetMapping("/15")
    public String executeViaAspectSafe05(@RequestParam String command) {
        // 安全：使用切面的安全实现执行命令
        return commandExecutionAspect.executeCommandSafe(command);
    }

    /**
     * 测试用例16：使用ProcessBuilder添加参数方式
     */
    @GetMapping("/16")
    public String executeWithProcessBuilderSafe06(@RequestParam String dir, @RequestParam String filter) throws IOException {
        // 安全：使用ProcessBuilder的command方法添加参数
        List<String> commands = new ArrayList<>();
        commands.add("ls");

        // 验证参数不包含特殊字符
        if (!filter.matches(".*[;&|`\\\\\"'$].*")) {
            if (filter.length() > 0) {
                commands.add("-la");
                commands.add(filter);
            }
        }

        ProcessBuilder processBuilder = new ProcessBuilder(commands);

        // 设置工作目录而不是在命令中使用cd
        if (dir != null && !dir.isEmpty() && !dir.contains("..")) {
            processBuilder.directory(new java.io.File(dir));
        }

        Process process = processBuilder.start();
        return readProcessOutput(process);
    }

    /**
     * 测试用例17：从配置文件读取并完全验证命令
     */
    @GetMapping("/17")
    public String executeWithFullValidation07(@RequestParam String command) throws IOException {
        // 安全：完全验证命令及其参数
        String[] allowedPrefixes = allowedCommandPrefix.split(",");
        String[] parts = command.split("\\s+", 2);

        if (parts.length > 0 && Arrays.asList(allowedPrefixes).contains(parts[0])) {
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
    }

    /**
     * 测试用例18：使用工具类安全执行命令
     */
    @GetMapping("/18")
    public String executeViaUtilsSafe08(@RequestParam String command) {
        return CommandUtils.executeSafe(command); // 安全：在工具类中验证命令
    }

    /**
     * 测试用例19：使用Java API替代命令行
     */
    @GetMapping("/19")
    public String executeWithJavaApiSafe09(@RequestParam String dir, @RequestParam String filter) {
        // 安全：使用Java API实现功能而不使用命令行
        try {
            java.nio.file.Path dirPath = java.nio.file.Paths.get(dir).normalize();

            // 验证路径是否在安全目录内
            if (dirPath.startsWith(java.nio.file.Paths.get("/safe/path").normalize())) {
                return java.nio.file.Files.list(dirPath)
                        .filter(path -> path.getFileName().toString().contains(filter))
                        .map(path -> path.getFileName().toString())
                        .collect(Collectors.joining("\n"));
            }
            return "Directory not allowed";
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 测试用例20：使用安全的文件API替代命令行
     */
    @GetMapping("/20")
    public String fileOperationWithApiSafe10(@RequestParam String fileName) {
        // 安全：使用Java文件API代替命令行读取文件
        try {
            java.nio.file.Path filePath = java.nio.file.Paths.get(fileName).normalize();

            // 验证文件路径是否在安全目录内
            if (filePath.startsWith(java.nio.file.Paths.get("/safe/path").normalize())) {
                return new String(java.nio.file.Files.readAllBytes(filePath));
            }
            return "File access not allowed";
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
