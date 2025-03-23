package edu.thu.benchmark.annotated.service.impl;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import edu.thu.benchmark.annotated.entity.FileInfo;
import edu.thu.benchmark.annotated.service.FileService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class FileServiceImpl implements FileService {

    @Value("${file.upload.dir:./uploads}")
    private String uploadDir;

    private final Path rootLocation;
    private final List<FileInfo> fileInfoList = new ArrayList<>();
    private final AtomicInteger fileIdCounter = new AtomicInteger(1);

    public FileServiceImpl(@Value("${file.upload.dir:./uploads}") String uploadDir) {
        this.uploadDir = uploadDir;
        this.rootLocation = Paths.get(uploadDir);
    }

    @Override
    public void init() throws IOException {
        Files.createDirectories(rootLocation);
    }

    @Override
    public FileInfo store(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IOException("无法存储空文件");
        }

        String filename = file.getOriginalFilename();
        if (filename == null || filename.contains("..")) {
            throw new IOException("存储文件失败，文件名无效");
        }

        // 创建文件路径
        Path destinationFile = this.rootLocation.resolve(filename).normalize();

        // 检查目标文件是否在uploadDir目录下（防止路径遍历）
        if (!destinationFile.getParent().equals(this.rootLocation.normalize())) {
            throw new IOException("无法存储文件到指定目录外");
        }

        // 保存文件
        try (InputStream inputStream = file.getInputStream()) {
            Files.copy(inputStream, destinationFile, StandardCopyOption.REPLACE_EXISTING);
        }

        // 创建文件信息对象
        FileInfo fileInfo = new FileInfo(
                filename,
                destinationFile.toString(),
                file.getContentType(),
                file.getSize()
        );
        fileInfo.setId(fileIdCounter.getAndIncrement());
        fileInfoList.add(fileInfo);

        return fileInfo;
    }

    @Override
    public Resource loadByFilename(String filename) {
        try {
            Path file = rootLocation.resolve(filename);
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            } else {
                return null;
            }
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public Resource loadById(Integer id) {
        FileInfo fileInfo = fileInfoList.stream()
                .filter(info -> info.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (fileInfo == null) {
            return null;
        }

        try {
            Path file = Paths.get(fileInfo.getFilepath());
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            } else {
                return null;
            }
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Vulnerability(
            type = VulnerabilityType.PATH_TRAVERSAL,
            cwe = 22,
            description = "此方法存在路径遍历漏洞，允许攻击者通过操纵path参数来读取服务器上任意路径的文件",
            remediation = "应验证路径是否在预期的目录内，可以使用isPathSafe方法",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    @Override
    public Resource loadByPath(String path) {
        try {
            // 不安全的实现 - 路径遍历漏洞
            Path file = Paths.get(path);
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            } else {
                return null;
            }
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public List<FileInfo> getAllFiles() {
        return fileInfoList;
    }

    @Override
    public boolean deleteFile(Integer id) {
        FileInfo fileInfo = fileInfoList.stream()
                .filter(info -> info.getId().equals(id))
                .findFirst()
                .orElse(null);

        if (fileInfo == null) {
            return false;
        }

        try {
            Path file = Paths.get(fileInfo.getFilepath());
            if (Files.deleteIfExists(file)) {
                fileInfoList.remove(fileInfo);
                return true;
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public Path getFilePath(String filename) {
        return rootLocation.resolve(filename);
    }

    @Override
    public boolean isPathSafe(Path path) {
        try {
            Path normalizedPath = path.normalize();
            Path normalizedRoot = rootLocation.normalize();

            // 检查路径是否以根目录开头
            return normalizedPath.startsWith(normalizedRoot);
        } catch (Exception e) {
            return false;
        }
    }

    // 不安全的辅助方法 - 用于演示目的
    public String readFileContentUnsafe(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path)));
    }

    // 安全的辅助方法
    public String readFileContentSafe(String filename) throws IOException {
        Path filePath = getFilePath(filename).normalize();
        if (!isPathSafe(filePath)) {
            throw new IOException("访问被拒绝：无法访问指定目录外的文件");
        }
        return new String(Files.readAllBytes(filePath));
    }
}
