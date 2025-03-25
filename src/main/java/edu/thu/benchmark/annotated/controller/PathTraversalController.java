package edu.thu.benchmark.annotated.controller;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import edu.thu.benchmark.annotated.aspect.FileAccessAspect;
import edu.thu.benchmark.annotated.service.PathTraversalService;
import edu.thu.benchmark.annotated.service.TemplateService;
import edu.thu.benchmark.annotated.service.ZipService;
import edu.thu.benchmark.annotated.util.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * 路径遍历测试控制器
 * 包含40个测试用例，20个正例（存在漏洞）和20个负例（安全实现）
 */
@RestController
@RequestMapping("/path")
public class PathTraversalController {

    // 原注解: @Value("${file.base.dir}")
    private String baseDir = "/tmp/files";

    // 原注解: @Autowired
    private PathTraversalService pathTraversalService = new PathTraversalService();

    // 原注解: @Autowired
    private TemplateService templateService = new TemplateService();

    // 原注解: @Autowired
    private FileAccessAspect fileAccessAspect = new FileAccessAspect();

    // ======== 测试用例 - 正例（存在路径遍历漏洞） ========

    /**
     * 测试用例1：直接拼接文件路径 - 不安全实现
     */
    @GetMapping("/01")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "直接拼接用户输入的文件名到基本路径中没有进行验证",
            remediation = "使用规范化路径并验证最终路径是否在允许的目录内",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public ResponseEntity<Resource> getFile01(@RequestParam String filename) {
        File file = new File(baseDir + "/" + filename); // 不安全：直接拼接路径
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                .body(new FileSystemResource(file));
    }

    /**
     * 测试用例2：访问图片文件 - 不安全实现
     */
    @GetMapping("/02")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "从请求参数中获取图片名称后直接拼接到路径中",
            remediation = "对文件名进行验证，确保不包含../等路径遍历字符",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public ResponseEntity<Resource> getImage02(@RequestParam String imageName) {
        String imagePath = baseDir + "/images/" + imageName; // 不安全：直接拼接图片路径
        File imageFile = new File(imagePath);
        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_JPEG)
                .body(new FileSystemResource(imageFile));
    }

    /**
     * 测试用例3：文件下载 - 不安全实现
     */
    @GetMapping("/03")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "通过File构造函数直接使用用户输入的路径",
            remediation = "使用Path.normalize()和Path.startsWith()验证路径合法性",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    public ResponseEntity<Resource> downloadFile03(@RequestParam String filePath) {
        File file = new File(baseDir, filePath); // 不安全：直接使用用户输入构造File对象
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                .body(new FileSystemResource(file));
    }

    /**
     * 测试用例4：读取文件内容 - 不安全实现
     */
    @GetMapping("/04")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "使用FileInputStream直接读取用户指定的文件而不验证路径",
            remediation = "对文件路径进行白名单验证或使用Path API验证路径",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String readFileContent04(@RequestParam String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (FileInputStream fis = new FileInputStream(baseDir + "/" + filePath); // 不安全：直接拼接路径
             BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }

    /**
     * 测试用例5：通过依赖注入的Service读取文件 - 不安全实现
     */
    @GetMapping("/05")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "通过依赖注入的Service直接读取用户提供的文件路径",
            remediation = "在Service层实现路径验证逻辑",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String getFileWithInjection05(@RequestParam String filePath) {
        return pathTraversalService.readFileUnsafe(filePath); // 不安全：在Service中未验证路径
    }

    /**
     * 测试用例6：读取XML文件 - 不安全实现
     */
    @GetMapping("/06")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "直接使用XML文件路径而不进行验证",
            remediation = "对XML文件路径进行验证，确保在安全目录中",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String getXmlFile06(@RequestParam String xmlFile) throws IOException {
        File file = new File(baseDir + "/config/" + xmlFile); // 不安全：直接拼接XML文件路径
        return new String(Files.readAllBytes(file.toPath()));
    }

    /**
     * 测试用例7：通过AOP切面获取日志文件 - 不安全实现
     */
    @GetMapping("/07")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "通过AOP切面获取日志文件但不验证路径",
            remediation = "在AOP切面中实现路径验证逻辑",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    public String getLogFile07(@RequestParam String logFile) {
        // 不安全：通过切面执行的文件访问但切面中未验证路径
        return fileAccessAspect.accessLogFile(baseDir + "/logs/" + logFile);
    }

    /**
     * 测试用例8：读取配置文件 - 不安全实现
     */
    @GetMapping("/08")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "使用配置文件路径但允许使用../等字符",
            remediation = "过滤或规范化输入中的../等路径遍历字符",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public Map<String, String> getConfigFile08(@RequestParam String configFile) throws IOException {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(baseDir + "/config/" + configFile)) { // 不安全：未过滤../等字符
            props.load(fis);
        }
        return (Map) props;
    }

    /**
     * 测试用例9：读取属性文件 - 不安全实现
     */
    @GetMapping("/09")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "读取属性文件时使用拼接的相对路径",
            remediation = "使用ClassPathResource或验证路径是否在预期目录",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public Map<String, String> readProperties09(@RequestParam String propFile) throws IOException {
        Properties props = new Properties();
        File file = new File("./config/" + propFile); // 不安全：使用相对路径
        try (FileInputStream fis = new FileInputStream(file)) {
            props.load(fis);
        }
        return (Map) props;
    }

    /**
     * 测试用例10：获取模板文件 - 不安全实现
     */
    @GetMapping("/10")
    @Vulnerability(
            cwe = 22,
            type = VulnerabilityType.PATH_TRAVERSAL,
            description = "获取模板文件时未验证路径",
            remediation = "对模板文件路径进行白名单验证",
            level = VulnerabilityLevel.MEDIUM,
            isRealVulnerability = true
    )
    public String getTemplateFile10(@RequestParam String template) {
        return templateService.getTemplateUnsafe(template); // 不安全：在Service中未验证模板路径
    }

    // 其他不安全实现的测试用例省略...

    // ======== 测试用例 - 负例（安全实现） ========

    /**
     * 测试用例21：直接拼接文件路径 - 安全实现
     */
    @GetMapping("/21")
    public ResponseEntity<Resource> getFileSafe01(@RequestParam String filename) throws IOException {
        // 安全：规范化路径并验证
        Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();

        // 验证最终路径是否在允许的目录内
        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Access to the file is not allowed");
        }

        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found");
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filePath.getFileName() + "\"")
                .body(new FileSystemResource(filePath.toFile()));
    }

    /**
     * 测试用例22：访问图片文件 - 安全实现
     */
    @GetMapping("/22")
    public ResponseEntity<Resource> getImageSafe02(@RequestParam String imageName) {
        // 安全：验证文件名不包含路径遍历字符
        if (imageName.contains("..") || imageName.contains("/") || imageName.contains("\\")) {
            throw new SecurityException("Invalid image name");
        }

        // 进一步验证：只允许特定扩展名
        if (!imageName.toLowerCase().endsWith(".jpg") &&
            !imageName.toLowerCase().endsWith(".png") &&
            !imageName.toLowerCase().endsWith(".gif")) {
            throw new SecurityException("Invalid image type");
        }

        Path basePath = Paths.get(baseDir, "images").toAbsolutePath().normalize();
        Path imagePath = basePath.resolve(imageName).normalize();

        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_JPEG)
                .body(new FileSystemResource(imagePath.toFile()));
    }

    /**
     * 测试用例23：文件下载 - 安全实现
     */
    @GetMapping("/23")
    public ResponseEntity<Resource> downloadFileSafe03(@RequestParam String filePath) throws IOException {
        // 安全：规范化路径并验证
        Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolvedPath = basePath.resolve(filePath).normalize();

        // 验证最终路径是否在允许的目录内
        if (!resolvedPath.startsWith(basePath)) {
            throw new SecurityException("Access to the file is not allowed");
        }

        if (!Files.exists(resolvedPath)) {
            throw new FileNotFoundException("File not found");
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resolvedPath.getFileName() + "\"")
                .body(new FileSystemResource(resolvedPath.toFile()));
    }

    /**
     * 测试用例24：读取文件内容 - 安全实现
     */
    @GetMapping("/24")
    public String readFileContentSafe04(@RequestParam String filePath) throws IOException {
        // 安全：规范化路径并验证
        Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolvedPath = basePath.resolve(filePath).normalize();

        // 验证最终路径是否在允许的目录内
        if (!resolvedPath.startsWith(basePath)) {
            throw new SecurityException("Access to the file is not allowed");
        }

        if (!Files.isRegularFile(resolvedPath)) {
            throw new FileNotFoundException("File not found or not a regular file");
        }

        return new String(Files.readAllBytes(resolvedPath));
    }

    /**
     * 测试用例25：通过依赖注入的Service读取文件 - 安全实现
     */
    @GetMapping("/25")
    public String getFileWithInjectionSafe05(@RequestParam String filePath) {
        return pathTraversalService.readFileSafe(filePath); // 安全：在Service中验证路径
    }

    /**
     * 测试用例26：读取XML文件 - 安全实现
     */
    @GetMapping("/26")
    public String getXmlFileSafe06(@RequestParam String xmlFile) throws IOException {
        // 安全：验证文件名格式和扩展名
        if (xmlFile.contains("..") || xmlFile.contains("/") || xmlFile.contains("\\")) {
            throw new SecurityException("Invalid XML file name");
        }

        if (!xmlFile.toLowerCase().endsWith(".xml")) {
            throw new SecurityException("File must be an XML file");
        }

        Path basePath = Paths.get(baseDir, "config").toAbsolutePath().normalize();
        Path xmlPath = basePath.resolve(xmlFile).normalize();

        if (!xmlPath.startsWith(basePath)) {
            throw new SecurityException("Access to the XML file is not allowed");
        }

        return new String(Files.readAllBytes(xmlPath));
    }

    /**
     * 测试用例27：通过AOP切面获取日志文件 - 安全实现
     */
    @GetMapping("/27")
    public String getLogFileSafe07(@RequestParam String logFile) {
        // 安全：验证文件名
        if (logFile.contains("..") || logFile.contains("/") || logFile.contains("\\")) {
            throw new SecurityException("Invalid log file name");
        }

        if (!logFile.toLowerCase().endsWith(".log")) {
            throw new SecurityException("File must be a log file");
        }

        // 使用安全的切面实现
        return fileAccessAspect.accessLogFileSafe(logFile);
    }

    /**
     * 测试用例28：读取配置文件 - 安全实现
     */
    @GetMapping("/28")
    public Map<String, String> getConfigFileSafe08(@RequestParam String configFile) throws IOException {
        // 安全：验证文件名
        if (configFile.contains("..") || configFile.contains("/") || configFile.contains("\\")) {
            throw new SecurityException("Invalid config file name");
        }

        if (!configFile.toLowerCase().endsWith(".properties") && !configFile.toLowerCase().endsWith(".xml")) {
            throw new SecurityException("Invalid config file type");
        }

        Path basePath = Paths.get(baseDir, "config").toAbsolutePath().normalize();
        Path configPath = basePath.resolve(configFile).normalize();

        if (!configPath.startsWith(basePath)) {
            throw new SecurityException("Access to the config file is not allowed");
        }

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
            props.load(fis);
        }
        return (Map) props;
    }

    /**
     * 测试用例29：读取属性文件 - 安全实现
     */
    @GetMapping("/29")
    public Map<String, String> readPropertiesSafe09(@RequestParam String propFile) throws IOException {
        // 安全：使用ClassPathResource从类路径加载资源
        if (!propFile.endsWith(".properties")) {
            throw new SecurityException("File must be a properties file");
        }

        ClassPathResource resource = new ClassPathResource("config/" + propFile);
        Properties props = new Properties();
        try (InputStream is = resource.getInputStream()) {
            props.load(is);
        }
        return (Map) props;
    }

    /**
     * 测试用例30：获取模板文件 - 安全实现
     */
    @GetMapping("/30")
    public String getTemplateFileSafe10(@RequestParam String template) {
        // 白名单验证模板名称
        if (!template.matches("[a-zA-Z0-9_-]+\\.html")) {
            throw new SecurityException("Invalid template name");
        }

        return templateService.getTemplateSafe(template); // 安全：在Service中验证模板路径
    }

    // 其他安全实现的测试用例省略...
}
