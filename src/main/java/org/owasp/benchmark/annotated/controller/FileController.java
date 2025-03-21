package org.owasp.benchmark.annotated.controller;

import org.owasp.benchmark.annotated.annotation.Vulnerability;
import org.owasp.benchmark.annotated.entity.FileInfo;
import org.owasp.benchmark.annotated.annotation.VulnerabilityType;
import org.owasp.benchmark.annotated.annotation.VulnerabilityLevel;
import org.owasp.benchmark.annotated.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/files")
public class FileController {

    private final FileService fileService;
    
    @Autowired
    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping
    public String filePage(Model model) {
        model.addAttribute("files", fileService.getAllFiles());
        return "files";
    }

    @PostMapping("/upload")
    @ResponseBody
    public Map<String, Object> uploadFile(@RequestParam("file") MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            FileInfo fileInfo = fileService.store(file);
            
            response.put("success", true);
            response.put("fileId", fileInfo.getId());
            response.put("message", "文件上传成功");
            
        } catch (IOException e) {
            response.put("success", false);
            response.put("message", "文件上传失败: " + e.getMessage());
        }
        
        return response;
    }

    @GetMapping("/list")
    @ResponseBody
    public List<FileInfo> listFiles() {
        return fileService.getAllFiles();
    }

    @Vulnerability(
            type = VulnerabilityType.PATH_TRAVERSAL,
            cweNumber = 22,
            description = "此方法存在路径遍历漏洞，允许攻击者通过操纵filename参数来访问服务器上任意路径的文件",
            remediation = "使用Path.normalize()并确保文件路径在预期目录内，验证用户输入并防止相对路径突破",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    @GetMapping("/view/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> viewFile(@PathVariable String filename) {
        // 不安全的实现 - 直接使用用户提供的文件名，容易受到路径遍历攻击
        Resource resource = fileService.loadByFilename(filename);
        
        if (resource != null && resource.exists()) {
            try {
                String contentType = "application/octet-stream";
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType(contentType))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                        .body(resource);
            } catch (Exception e) {
                return ResponseEntity.badRequest().build();
            }
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Vulnerability(
            type = VulnerabilityType.PATH_TRAVERSAL,
            cweNumber = 22,
            description = "此方法存在路径遍历漏洞，允许攻击者通过操纵filepath参数来读取服务器上任意路径的文件",
            remediation = "不应接受用户提供的完整文件路径，而应使用文件ID或其他方式确定安全的文件访问",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    @GetMapping("/read")
    @ResponseBody
    public ResponseEntity<String> readFile(@RequestParam String filepath) {
        try {
            // 极其不安全的实现 - 严重的路径遍历漏洞
            // 直接接受用户提供的文件路径
            Resource resource = fileService.loadByPath(filepath);
            
            if (resource != null && resource.exists()) {
                String content = new String(Files.readAllBytes(Paths.get(filepath)));
                return ResponseEntity.ok(content);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (IOException e) {
            return ResponseEntity.badRequest().body("无法读取文件: " + e.getMessage());
        }
    }

    @GetMapping("/download/{id}")
    @ResponseBody
    public ResponseEntity<Resource> downloadFile(@PathVariable Integer id) {
        // 安全实现 - 通过ID查找文件，避免路径遍历
        Resource resource = fileService.loadById(id);
        
        if (resource != null && resource.exists()) {
            try {
                String contentType = "application/octet-stream";
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType(contentType))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                        .body(resource);
            } catch (Exception e) {
                return ResponseEntity.badRequest().build();
            }
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    
    @PostMapping("/delete/{id}")
    @ResponseBody
    public Map<String, Object> deleteFile(@PathVariable Integer id) {
        Map<String, Object> response = new HashMap<>();
        
        boolean success = fileService.deleteFile(id);
        
        response.put("success", success);
        response.put("message", success ? "文件删除成功" : "文件删除失败");
        
        return response;
    }
} 