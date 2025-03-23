package edu.thu.benchmark.annotated.controller;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/http")
public class HttpController {

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.).*");

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping
    public String httpPage() {
        return "http";
    }

    @Vulnerability(
            type = VulnerabilityType.SSRF,
            cwe = 918,
            description = "此方法存在服务端请求伪造(SSRF)漏洞，允许攻击者使用服务器向内部网络发起请求",
            remediation = "实施URL验证，仅允许已知域名和公共IP地址，禁止访问内部网络",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    @GetMapping("/fetch")
    @ResponseBody
    public ResponseEntity<String> fetchUrl(@RequestParam String url) {
        try {
            // 不安全的实现 - 直接使用用户提供的URL发起请求
            String content = restTemplate.getForObject(url, String.class);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("请求失败: " + e.getMessage());
        }
    }

    @Vulnerability(
            type = VulnerabilityType.SSRF,
            cwe = 918,
            description = "此方法存在服务端请求伪造(SSRF)漏洞，使用底层HttpURLConnection",
            remediation = "验证URL是否指向允许的目标，过滤内部IP和保留地址",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    @GetMapping("/connect")
    @ResponseBody
    public Map<String, Object> connectUrl(@RequestParam String targetUrl) {
        Map<String, Object> response = new HashMap<>();
        StringBuilder content = new StringBuilder();

        try {
            // 创建URL连接
            URL url = new URL(targetUrl);
            URLConnection connection = url.openConnection();

            if (connection instanceof HttpURLConnection) {
                HttpURLConnection httpConnection = (HttpURLConnection) connection;
                httpConnection.setRequestMethod("GET");

                // 读取响应
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(httpConnection.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        content.append(line).append("\n");
                    }
                }

                response.put("statusCode", httpConnection.getResponseCode());
                response.put("statusMessage", httpConnection.getResponseMessage());
                response.put("content", content.toString());
                response.put("contentType", httpConnection.getContentType());
                response.put("success", true);
            } else {
                response.put("success", false);
                response.put("message", "不支持的协议");
            }
        } catch (IOException e) {
            response.put("success", false);
            response.put("message", "连接失败: " + e.getMessage());
        }

        return response;
    }

    @GetMapping("/fetch-safe")
    @ResponseBody
    public ResponseEntity<String> fetchUrlSafe(@RequestParam String url) {
        try {
            // 安全实现 - 验证URL是否指向允许的目标
            URL targetUrl = new URL(url);
            String host = targetUrl.getHost();

            // 检查内部IP
            if (IP_PATTERN.matcher(host).matches()) {
                return ResponseEntity.badRequest().body("禁止访问内部网络");
            }

            // 检查协议
            if (!targetUrl.getProtocol().equalsIgnoreCase("https") &&
                !targetUrl.getProtocol().equalsIgnoreCase("http")) {
                return ResponseEntity.badRequest().body("只允许HTTP和HTTPS协议");
            }

            // 允许列表检查
            if (!isAllowedHost(host)) {
                return ResponseEntity.badRequest().body("域名不在允许列表中");
            }

            // 发起请求
            String content = restTemplate.getForObject(url, String.class);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("请求失败: " + e.getMessage());
        }
    }

    // 检查域名是否在允许列表中
    private boolean isAllowedHost(String host) {
        String[] allowedHosts = {
            "example.com",
            "api.github.com",
            "api.openweathermap.org"
            // 添加其他允许的域名
        };

        for (String allowedHost : allowedHosts) {
            if (host.endsWith(allowedHost)) {
                return true;
            }
        }

        return false;
    }
}
