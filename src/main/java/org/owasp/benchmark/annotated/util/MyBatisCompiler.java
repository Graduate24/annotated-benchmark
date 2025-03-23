package org.owasp.benchmark.annotated.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MyBatis编译器工具
 * 用于将MyBatis XML文件和Java接口方法编译为完整的调用路径
 */
public class MyBatisCompiler {
    
    /**
     * 编译后的方法路径信息
     */
    private final Map<String, List<MethodInfo>> compiledMethods = new HashMap<>();
    
    /**
     * XML解析器信息
     */
    private final List<MyBatisXmlParser.MapperInfo> xmlMappers = new ArrayList<>();
    
    /**
     * 输出目录
     */
    private final String outputDir;
    
    /**
     * 构造函数
     *
     * @param outputDir 输出目录
     */
    public MyBatisCompiler(String outputDir) {
        this.outputDir = outputDir;
        // 确保输出目录存在
        new File(outputDir).mkdirs();
    }
    
    /**
     * 解析XML文件
     *
     * @param xmlPaths XML文件路径列表
     * @return 当前实例，用于链式调用
     */
    public MyBatisCompiler parseXmlFiles(List<String> xmlPaths) {
        for (String path : xmlPaths) {
            MyBatisXmlParser.MapperInfo mapperInfo = MyBatisXmlParser.parseXml(path);
            if (mapperInfo.getNamespace() != null && !mapperInfo.getNamespace().isEmpty()) {
                xmlMappers.add(mapperInfo);
            }
        }
        return this;
    }
    
    /**
     * 解析目录中的XML文件
     *
     * @param directory 目录路径
     * @return 当前实例，用于链式调用
     */
    public MyBatisCompiler parseDirectory(String directory) {
        xmlMappers.addAll(MyBatisXmlParser.parseDirectory(directory));
        return this;
    }
    
    /**
     * 编译方法路径
     */
    public void compile() {
        for (MyBatisXmlParser.MapperInfo mapperInfo : xmlMappers) {
            String namespace = mapperInfo.getNamespace();
            List<MethodInfo> methods = new ArrayList<>();
            
            for (MyBatisXmlParser.SqlInfo sqlInfo : mapperInfo.getSqlInfoList()) {
                MethodInfo methodInfo = new MethodInfo();
                methodInfo.setFullPath(MyBatisXmlParser.getFullMethodPath(namespace, sqlInfo.getId()));
                methodInfo.setMapperClass(namespace);
                methodInfo.setMethodName(sqlInfo.getId());
                methodInfo.setSqlType(sqlInfo.getType().toUpperCase());
                methodInfo.setResultType(sqlInfo.getResultType());
                methodInfo.setParameterType(sqlInfo.getParameterType());
                methodInfo.setSqlContent(sqlInfo.getSqlContent());
                
                methods.add(methodInfo);
            }
            
            compiledMethods.put(namespace, methods);
        }
    }
    
    /**
     * 保存编译结果到类常量文件
     */
    public void saveToConstantsFile() {
        try (FileWriter writer = new FileWriter(outputDir + "/MyBatisMethodConstants.java")) {
            writer.write("package org.owasp.benchmark.annotated.util;\n\n");
            writer.write("/**\n");
            writer.write(" * MyBatis方法路径常量类\n");
            writer.write(" * 该类由工具自动生成，请勿手动修改\n");
            writer.write(" */\n");
            writer.write("public final class MyBatisMethodConstants {\n\n");
            
            // 生成内部接口，每个命名空间一个
            for (Map.Entry<String, List<MethodInfo>> entry : compiledMethods.entrySet()) {
                String namespace = entry.getKey();
                List<MethodInfo> methods = entry.getValue();
                
                String className = namespace.substring(namespace.lastIndexOf('.') + 1);
                
                writer.write("    /**\n");
                writer.write("     * " + className + " 方法路径\n");
                writer.write("     */\n");
                writer.write("    public static final class " + className + " {\n");
                
                for (MethodInfo method : methods) {
                    writer.write("        /**\n");
                    writer.write("         * " + method.getSqlType() + " 操作: " + method.getMethodName() + "\n");
                    if (method.getResultType() != null) {
                        writer.write("         * 返回类型: " + method.getResultType() + "\n");
                    }
                    if (method.getParameterType() != null) {
                        writer.write("         * 参数类型: " + method.getParameterType() + "\n");
                    }
                    writer.write("         */\n");
                    
                    // 常量名使用大写字母加下划线形式
                    String constantName = toConstantName(method.getMethodName());
                    writer.write("        public static final String " + constantName + " = \"" + method.getFullPath() + "\";\n\n");
                }
                
                writer.write("    }\n\n");
            }
            
            writer.write("    private MyBatisMethodConstants() {\n");
            writer.write("        // 私有构造函数，防止实例化\n");
            writer.write("    }\n");
            writer.write("}\n");
            
        } catch (IOException e) {
            System.err.println("保存常量文件时出错: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 保存编译结果到方法调用示例文件
     */
    public void saveToExampleFile() {
        try (FileWriter writer = new FileWriter(outputDir + "/MyBatisCallExamples.java")) {
            writer.write("package org.owasp.benchmark.annotated.util;\n\n");
            writer.write("import org.springframework.beans.factory.annotation.Autowired;\n\n");
            
            for (String namespace : compiledMethods.keySet()) {
                writer.write("import " + namespace + ";\n");
            }
            
            writer.write("\n/**\n");
            writer.write(" * MyBatis方法调用示例类\n");
            writer.write(" * 该类由工具自动生成，仅用于参考\n");
            writer.write(" */\n");
            writer.write("public class MyBatisCallExamples {\n\n");
            
            // 注入所有Mapper接口
            for (String namespace : compiledMethods.keySet()) {
                String className = namespace.substring(namespace.lastIndexOf('.') + 1);
                String varName = Character.toLowerCase(className.charAt(0)) + className.substring(1);
                
                writer.write("    @Autowired\n");
                writer.write("    private " + className + " " + varName + ";\n");
            }
            
            writer.write("\n    /**\n");
            writer.write("     * 演示所有方法调用\n");
            writer.write("     */\n");
            writer.write("    public void demonstrateAllCalls() {\n");
            
            // 为每个Mapper生成调用示例
            for (Map.Entry<String, List<MethodInfo>> entry : compiledMethods.entrySet()) {
                String namespace = entry.getKey();
                List<MethodInfo> methods = entry.getValue();
                
                String className = namespace.substring(namespace.lastIndexOf('.') + 1);
                String varName = Character.toLowerCase(className.charAt(0)) + className.substring(1);
                
                writer.write("\n        // " + className + " 调用示例\n");
                
                for (MethodInfo method : methods) {
                    writer.write("        // " + method.getSqlType() + ": " + method.getMethodName() + "\n");
                    writer.write("        try {\n");
                    
                    if ("SELECT".equals(method.getSqlType())) {
                        if (method.getResultType() != null) {
                            String resultType = getSimpleTypeName(method.getResultType());
                            writer.write("            " + resultType + " result = " + varName + "." + method.getMethodName() + "();\n");
                            writer.write("            System.out.println(\"执行 " + method.getFullPath() + " 结果: \" + result);\n");
                        } else {
                            writer.write("            Object result = " + varName + "." + method.getMethodName() + "();\n");
                            writer.write("            System.out.println(\"执行 " + method.getFullPath() + " 结果: \" + result);\n");
                        }
                    } else {
                        writer.write("            int affected = " + varName + "." + method.getMethodName() + "();\n");
                        writer.write("            System.out.println(\"执行 " + method.getFullPath() + " 影响行数: \" + affected);\n");
                    }
                    
                    writer.write("        } catch (Exception e) {\n");
                    writer.write("            System.err.println(\"执行 " + method.getFullPath() + " 出错: \" + e.getMessage());\n");
                    writer.write("        }\n\n");
                }
            }
            
            writer.write("    }\n");
            writer.write("}\n");
            
        } catch (IOException e) {
            System.err.println("保存示例文件时出错: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 将方法名转换为常量名（大写加下划线）
     */
    private String toConstantName(String methodName) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < methodName.length(); i++) {
            char c = methodName.charAt(i);
            if (Character.isUpperCase(c) && i > 0) {
                sb.append('_');
            }
            sb.append(Character.toUpperCase(c));
        }
        return sb.toString();
    }
    
    /**
     * 获取简化的类型名称
     */
    private String getSimpleTypeName(String fullTypeName) {
        if (fullTypeName == null) return "Object";
        
        if (fullTypeName.contains("<")) {
            // 处理泛型类型
            String baseType = fullTypeName.substring(0, fullTypeName.indexOf('<'));
            String genericType = fullTypeName.substring(fullTypeName.indexOf('<') + 1, fullTypeName.lastIndexOf('>'));
            
            return getSimpleTypeName(baseType) + "<" + getSimpleTypeName(genericType) + ">";
        } else {
            return fullTypeName.substring(fullTypeName.lastIndexOf('.') + 1);
        }
    }
    
    /**
     * 方法信息类
     */
    public static class MethodInfo {
        private String fullPath;
        private String mapperClass;
        private String methodName;
        private String sqlType;
        private String resultType;
        private String parameterType;
        private String sqlContent;
        
        public String getFullPath() {
            return fullPath;
        }
        
        public void setFullPath(String fullPath) {
            this.fullPath = fullPath;
        }
        
        public String getMapperClass() {
            return mapperClass;
        }
        
        public void setMapperClass(String mapperClass) {
            this.mapperClass = mapperClass;
        }
        
        public String getMethodName() {
            return methodName;
        }
        
        public void setMethodName(String methodName) {
            this.methodName = methodName;
        }
        
        public String getSqlType() {
            return sqlType;
        }
        
        public void setSqlType(String sqlType) {
            this.sqlType = sqlType;
        }
        
        public String getResultType() {
            return resultType;
        }
        
        public void setResultType(String resultType) {
            this.resultType = resultType;
        }
        
        public String getParameterType() {
            return parameterType;
        }
        
        public void setParameterType(String parameterType) {
            this.parameterType = parameterType;
        }
        
        public String getSqlContent() {
            return sqlContent;
        }
        
        public void setSqlContent(String sqlContent) {
            this.sqlContent = sqlContent;
        }
    }
    
    /**
     * 主方法，用于测试
     */
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("用法: java MyBatisCompiler <资源目录> <输出目录>");
            System.out.println("例如: java MyBatisCompiler ./src/main/resources/mapper ./src/main/java/org/example/mybatis");
            return;
        }
        
        String resourceDir = args[0];
        String outputDir = args[1];
        
        MyBatisCompiler compiler = new MyBatisCompiler(outputDir);
        compiler.parseDirectory(resourceDir);
        compiler.compile();
        
        // 保存编译结果
        compiler.saveToConstantsFile();
        compiler.saveToExampleFile();
        
        System.out.println("编译完成，输出目录: " + outputDir);
    }
} 