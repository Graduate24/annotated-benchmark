package org.owasp.benchmark.annotated.service;

import org.owasp.benchmark.annotated.entity.FileInfo;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * 文件服务接口
 */
public interface FileService {
    
    /**
     * 初始化文件存储
     */
    void init() throws IOException;
    
    /**
     * 存储文件
     * @param file 要存储的文件
     * @return 存储的文件信息
     */
    FileInfo store(MultipartFile file) throws IOException;
    
    /**
     * 根据文件名加载文件
     * @param filename 文件名
     * @return 文件资源
     */
    Resource loadByFilename(String filename);
    
    /**
     * 根据ID加载文件
     * @param id 文件ID
     * @return 文件资源
     */
    Resource loadById(Integer id);
    
    /**
     * 根据路径加载文件
     * @param path 文件路径
     * @return 文件资源
     */
    Resource loadByPath(String path);
    
    /**
     * 获取所有文件信息
     * @return 文件信息列表
     */
    List<FileInfo> getAllFiles();
    
    /**
     * 删除文件
     * @param id 文件ID
     * @return 是否删除成功
     */
    boolean deleteFile(Integer id);
    
    /**
     * 根据文件名获取文件路径
     * @param filename 文件名
     * @return 文件路径
     */
    Path getFilePath(String filename);
    
    /**
     * 验证文件路径是否安全(在上传目录内)
     * @param path 要验证的路径
     * @return 是否安全
     */
    boolean isPathSafe(Path path);
} 