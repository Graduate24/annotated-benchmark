package org.owasp.benchmark.annotated.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * MyBatis Mapper 扫描器
 * 用于扫描Maven项目结构中的MyBatis XML文件，提取方法名并生成代码
 */
public class MyBatisMapperScanner {

    // XML中SQL语句的正则表达式模式
    private static final Pattern NAMESPACE_PATTERN = Pattern.compile("namespace\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern SQL_ID_PATTERN = Pattern.compile("<(select|insert|update|delete)\\s+id\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern PARAM_TYPE_PATTERN = Pattern.compile("parameterType\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern RESULT_TYPE_PATTERN = Pattern.compile("resultType\\s*=\\s*\"([^\"]+)\"");

    /**
     * Maven项目的结构信息
     */
    private final String projectRoot;
    private final String resourcesDir;
    private final String javaSourceDir;
    private final String outputDir;

    /**
     * 构造函数
     *
     * @param projectRoot Maven项目根目录
     */
    public MyBatisMapperScanner(String projectRoot) {
        this.projectRoot = projectRoot;
        this.resourcesDir = projectRoot + "/src/main/resources";
        this.javaSourceDir = projectRoot + "/src/main/java";
        this.outputDir = projectRoot + "/target/generated-sources";
    }

    /**
     * 扫描资源目录中的MyBatis XML文件
     *
     * @return 扫描结果
     */
    public Map<String, List<SqlMethod>> scanMapperXml() {
        Map<String, List<SqlMethod>> result = new HashMap<>();
        
        try {
            // 查找所有XML文件
            List<Path> xmlFiles = Files.walk(Paths.get(resourcesDir))
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().toLowerCase().endsWith(".xml"))
                    .collect(Collectors.toList());
            
            for (Path xmlPath : xmlFiles) {
                try {
                    String content = Files.readString(xmlPath);
                    
                    // 提取namespace
                    Matcher namespaceMatcher = NAMESPACE_PATTERN.matcher(content);
                    if (namespaceMatcher.find()) {
                        String namespace = namespaceMatcher.group(1);
                        List<SqlMethod> methods = new ArrayList<>();
                        
                        // 提取SQL ID和类型
                        Matcher sqlMatcher = SQL_ID_PATTERN.matcher(content);
                        while (sqlMatcher.find()) {
                            String sqlType = sqlMatcher.group(1);
                            String sqlId = sqlMatcher.group(2);
                            
                            // 创建SQL方法对象
                            SqlMethod method = new SqlMethod(namespace, sqlId, sqlType);
                            
                            // 尝试提取参数类型
                            int sqlStart = content.indexOf(sqlMatcher.group(0));
                            int sqlEnd = content.indexOf(">", sqlStart);
                            String sqlDef = content.substring(sqlStart, sqlEnd);
                            
                            Matcher paramTypeMatcher = PARAM_TYPE_PATTERN.matcher(sqlDef);
                            if (paramTypeMatcher.find()) {
                                method.setParameterType(paramTypeMatcher.group(1));
                            }
                            
                            Matcher resultTypeMatcher = RESULT_TYPE_PATTERN.matcher(sqlDef);
                            if (resultTypeMatcher.find()) {
                                method.setResultType(resultTypeMatcher.group(1));
                            }
                            
                            methods.add(method);
                        }
                        
                        result.put(namespace, methods);
                    }
                } catch (IOException e) {
                    System.err.println("读取文件" + xmlPath + "时出错: " + e.getMessage());
                }
            }
            
        } catch (IOException e) {
            System.err.println("扫描资源目录时出错: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 生成Java接口代码
     *
     * @param mapperData 扫描到的Mapper数据
     */
    public void generateJavaInterfaces(Map<String, List<SqlMethod>> mapperData) {
        // 确保输出目录存在
        File outputDirFile = new File(outputDir);
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs();
        }
        
        for (Map.Entry<String, List<SqlMethod>> entry : mapperData.entrySet()) {
            String namespace = entry.getKey();
            List<SqlMethod> methods = entry.getValue();
            
            // 将命名空间转换为文件路径
            String packagePath = namespace.substring(0, namespace.lastIndexOf('.'));
            String className = namespace.substring(namespace.lastIndexOf('.') + 1);
            String filePath = outputDir + "/" + packagePath.replace('.', '/');
            
            // 确保包目录存在
            File packageDir = new File(filePath);
            if (!packageDir.exists()) {
                packageDir.mkdirs();
            }
            
            // 生成Java接口文件
            try (FileWriter writer = new FileWriter(filePath + "/" + className + ".java")) {
                writer.write("package " + packagePath + ";\n\n");
                
                // 导入
                writer.write("import org.apache.ibatis.annotations.Mapper;\n");
                writer.write("import org.apache.ibatis.annotations.Param;\n");
                writer.write("import java.util.List;\n\n");
                
                // 类定义
                writer.write("/**\n");
                writer.write(" * 自动生成的MyBatis Mapper接口\n");
                writer.write(" * 源自XML文件中的namespace: " + namespace + "\n");
                writer.write(" */\n");
                writer.write("@Mapper\n");
                writer.write("public interface " + className + " {\n\n");
                
                // 方法定义
                for (SqlMethod method : methods) {
                    writer.write("    /**\n");
                    writer.write("     * " + method.getSqlId() + "\n");
                    writer.write("     * SQL类型: " + method.getSqlType() + "\n");
                    if (method.getParameterType() != null) {
                        writer.write("     * 参数类型: " + method.getParameterType() + "\n");
                    }
                    if (method.getResultType() != null) {
                        writer.write("     * 返回类型: " + method.getResultType() + "\n");
                    }
                    writer.write("     */\n");
                    
                    // 简单生成方法签名
                    String returnType = method.getResultType() != null ? 
                            getSimpleTypeName(method.getResultType()) : "Object";
                    
                    if (method.getSqlType().equals("select")) {
                        if (returnType.contains("List")) {
                            writer.write("    List<" + extractGenericType(returnType) + "> " + method.getSqlId() + "();\n\n");
                        } else {
                            writer.write("    " + returnType + " " + method.getSqlId() + "();\n\n");
                        }
                    } else {
                        writer.write("    int " + method.getSqlId() + "();\n\n");
                    }
                }
                
                writer.write("}\n");
            } catch (IOException e) {
                System.err.println("生成Java接口文件时出错: " + e.getMessage());
            }
        }
    }
    
    /**
     * 检查Java源码目录中是否已存在Mapper接口
     *
     * @param mapperData 扫描到的Mapper数据
     * @return 已存在的Mapper接口列表
     */
    public List<String> checkExistingMappers(Map<String, List<SqlMethod>> mapperData) {
        List<String> existingMappers = new ArrayList<>();
        
        for (String namespace : mapperData.keySet()) {
            String javaFilePath = javaSourceDir + "/" + namespace.replace('.', '/') + ".java";
            File javaFile = new File(javaFilePath);
            if (javaFile.exists()) {
                existingMappers.add(namespace);
            }
        }
        
        return existingMappers;
    }
    
    /**
     * 生成调用示例代码
     *
     * @param mapperData 扫描到的Mapper数据
     * @return 生成的调用示例代码
     */
    public String generateSampleUsage(Map<String, List<SqlMethod>> mapperData) {
        StringBuilder sb = new StringBuilder();
        sb.append("// MyBatis Mapper方法调用示例\n\n");
        
        for (Map.Entry<String, List<SqlMethod>> entry : mapperData.entrySet()) {
            String namespace = entry.getKey();
            List<SqlMethod> methods = entry.getValue();
            
            String className = namespace.substring(namespace.lastIndexOf('.') + 1);
            String varName = Character.toLowerCase(className.charAt(0)) + className.substring(1);
            
            sb.append("// ").append(namespace).append(" 方法调用示例:\n");
            sb.append("@Autowired\nprivate ").append(className).append(" ").append(varName).append(";\n\n");
            
            for (SqlMethod method : methods) {
                sb.append("// ").append(method.getSqlType()).append(" 操作: ").append(method.getSqlId()).append("\n");
                
                if (method.getSqlType().equals("select")) {
                    if (method.getResultType() != null && method.getResultType().contains("List")) {
                        String genericType = extractGenericType(method.getResultType());
                        sb.append("List<").append(genericType).append("> result = ")
                          .append(varName).append(".").append(method.getSqlId()).append("();\n");
                    } else {
                        String returnType = method.getResultType() != null ? 
                                getSimpleTypeName(method.getResultType()) : "Object";
                        sb.append(returnType).append(" result = ")
                          .append(varName).append(".").append(method.getSqlId()).append("();\n");
                    }
                } else {
                    sb.append("int affected = ")
                      .append(varName).append(".").append(method.getSqlId()).append("();\n");
                }
                
                sb.append("\n");
            }
            
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * 获取简化的类型名称
     */
    private String getSimpleTypeName(String fullTypeName) {
        return fullTypeName.substring(fullTypeName.lastIndexOf('.') + 1);
    }
    
    /**
     * 从List类型中提取泛型类型
     */
    private String extractGenericType(String listType) {
        if (listType.contains("<") && listType.contains(">")) {
            return listType.substring(listType.indexOf('<') + 1, listType.lastIndexOf('>'));
        }
        return "Object";
    }
    
    /**
     * 主方法
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请提供Maven项目根目录路径");
            return;
        }
        
        MyBatisMapperScanner scanner = new MyBatisMapperScanner(args[0]);
        Map<String, List<SqlMethod>> mapperData = scanner.scanMapperXml();
        
        System.out.println("扫描到的Mapper信息:");
        for (Map.Entry<String, List<SqlMethod>> entry : mapperData.entrySet()) {
            System.out.println("\nNamespace: " + entry.getKey());
            for (SqlMethod method : entry.getValue()) {
                System.out.println("  - " + method.getSqlType() + ": " + method.getSqlId());
                if (method.getParameterType() != null) {
                    System.out.println("    参数类型: " + method.getParameterType());
                }
                if (method.getResultType() != null) {
                    System.out.println("    返回类型: " + method.getResultType());
                }
            }
        }
        
        // 检查是否有已存在的Mapper接口
        List<String> existingMappers = scanner.checkExistingMappers(mapperData);
        if (!existingMappers.isEmpty()) {
            System.out.println("\n已存在的Mapper接口:");
            for (String mapper : existingMappers) {
                System.out.println("  - " + mapper);
            }
        }
        
        // 生成Java接口
        System.out.println("\n正在生成Java接口...");
        scanner.generateJavaInterfaces(mapperData);
        System.out.println("Java接口生成完成，输出目录: " + scanner.outputDir);
        
        // 生成示例代码
        String sampleCode = scanner.generateSampleUsage(mapperData);
        try (FileWriter writer = new FileWriter(scanner.outputDir + "/MapperUsageExample.java")) {
            writer.write(sampleCode);
            System.out.println("调用示例代码已生成: " + scanner.outputDir + "/MapperUsageExample.java");
        } catch (IOException e) {
            System.err.println("生成示例代码时出错: " + e.getMessage());
        }
    }
    
    /**
     * SQL方法信息类
     */
    public static class SqlMethod {
        private final String namespace;
        private final String sqlId;
        private final String sqlType;
        private String parameterType;
        private String resultType;
        
        public SqlMethod(String namespace, String sqlId, String sqlType) {
            this.namespace = namespace;
            this.sqlId = sqlId;
            this.sqlType = sqlType;
        }
        
        public String getNamespace() {
            return namespace;
        }
        
        public String getSqlId() {
            return sqlId;
        }
        
        public String getSqlType() {
            return sqlType;
        }
        
        public String getParameterType() {
            return parameterType;
        }
        
        public void setParameterType(String parameterType) {
            this.parameterType = parameterType;
        }
        
        public String getResultType() {
            return resultType;
        }
        
        public void setResultType(String resultType) {
            this.resultType = resultType;
        }
        
        public String getFullMethodPath() {
            return namespace + "." + sqlId;
        }
    }
} 