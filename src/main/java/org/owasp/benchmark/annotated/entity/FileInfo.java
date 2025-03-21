package org.owasp.benchmark.annotated.entity;

import java.time.LocalDateTime;

/**
 * 文件信息实体类
 */
public class FileInfo {
    private Integer id;
    private String filename;
    private String filepath;
    private String contentType;
    private Long size;
    private LocalDateTime uploadTime;

    public FileInfo() {
    }

    public FileInfo(String filename, String filepath, String contentType, Long size) {
        this.filename = filename;
        this.filepath = filepath;
        this.contentType = contentType;
        this.size = size;
        this.uploadTime = LocalDateTime.now();
    }

    // Getters and Setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getFilepath() {
        return filepath;
    }

    public void setFilepath(String filepath) {
        this.filepath = filepath;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public Long getSize() {
        return size;
    }

    public void setSize(Long size) {
        this.size = size;
    }

    public LocalDateTime getUploadTime() {
        return uploadTime;
    }

    public void setUploadTime(LocalDateTime uploadTime) {
        this.uploadTime = uploadTime;
    }

    @Override
    public String toString() {
        return "FileInfo{" +
                "id=" + id +
                ", filename='" + filename + '\'' +
                ", filepath='" + filepath + '\'' +
                ", contentType='" + contentType + '\'' +
                ", size=" + size +
                ", uploadTime=" + uploadTime +
                '}';
    }
} 