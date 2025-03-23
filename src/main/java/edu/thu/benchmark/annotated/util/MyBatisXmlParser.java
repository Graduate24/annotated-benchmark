package edu.thu.benchmark.annotated.util;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * MyBatis XML解析工具
 * 用于解析MyBatis XML文件并提取namespace和SQL ID
 */
public class MyBatisXmlParser {

    private static final String[] SQL_TYPES = {"select", "insert", "update", "delete"};

    /**
     * 解析MyBatis XML文件
     *
     * @param xmlFile XML文件路径
     * @return 解析结果：包含命名空间和SQL方法信息
     */
    public static MapperInfo parseXml(String xmlFile) {
        MapperInfo result = new MapperInfo();

        try {
            // 创建DOM解析器
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new File(xmlFile));
            document.getDocumentElement().normalize();

            // 获取根元素并提取namespace
            Element root = document.getDocumentElement();
            String namespace = root.getAttribute("namespace");
            result.setNamespace(namespace);

            // 提取所有SQL语句
            for (String sqlType : SQL_TYPES) {
                NodeList nodes = document.getElementsByTagName(sqlType);
                for (int i = 0; i < nodes.getLength(); i++) {
                    Element element = (Element) nodes.item(i);
                    String id = element.getAttribute("id");
                    String resultType = element.getAttribute("resultType");
                    String parameterType = element.getAttribute("parameterType");

                    SqlInfo sqlInfo = new SqlInfo();
                    sqlInfo.setId(id);
                    sqlInfo.setType(sqlType);
                    if (!resultType.isEmpty()) {
                        sqlInfo.setResultType(resultType);
                    }
                    if (!parameterType.isEmpty()) {
                        sqlInfo.setParameterType(parameterType);
                    }

                    // 获取SQL语句内容
                    sqlInfo.setSqlContent(element.getTextContent().trim());

                    result.addSqlInfo(sqlInfo);
                }
            }

        } catch (ParserConfigurationException | SAXException | IOException e) {
            System.err.println("解析XML文件时出错: " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }

    /**
     * 解析指定目录下的所有MyBatis XML文件
     *
     * @param directory 目录路径
     * @return 解析结果列表
     */
    public static List<MapperInfo> parseDirectory(String directory) {
        List<MapperInfo> result = new ArrayList<>();

        try {
            // 查找目录下的所有XML文件
            List<Path> xmlFiles = Files.walk(Paths.get(directory))
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().toLowerCase().endsWith(".xml"))
                    .collect(Collectors.toList());

            for (Path path : xmlFiles) {
                MapperInfo info = parseXml(path.toString());
                if (info.getNamespace() != null && !info.getNamespace().isEmpty()) {
                    result.add(info);
                }
            }

        } catch (IOException e) {
            System.err.println("扫描目录时出错: " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }

    /**
     * 生成方法调用的完整路径
     *
     * @param namespace 命名空间
     * @param sqlId SQL ID
     * @return 完整方法路径
     */
    public static String getFullMethodPath(String namespace, String sqlId) {
        return namespace + "." + sqlId;
    }

    /**
     * 生成Java代码示例
     *
     * @param mapperInfoList Mapper信息列表
     * @return 生成的Java代码
     */
    public static String generateJavaExample(List<MapperInfo> mapperInfoList) {
        StringBuilder sb = new StringBuilder();
        sb.append("// 自动生成的MyBatis方法调用示例\n\n");

        for (MapperInfo mapperInfo : mapperInfoList) {
            String namespace = mapperInfo.getNamespace();
            String className = namespace.substring(namespace.lastIndexOf('.') + 1);
            String varName = Character.toLowerCase(className.charAt(0)) + className.substring(1);

            sb.append("// ").append(namespace).append(" 接口使用示例\n");
            sb.append("@Autowired\nprivate ").append(className).append(" ").append(varName).append(";\n\n");

            for (SqlInfo sqlInfo : mapperInfo.getSqlInfoList()) {
                sb.append("// ").append(sqlInfo.getType().toUpperCase()).append(": ").append(sqlInfo.getId()).append("\n");

                if ("select".equals(sqlInfo.getType())) {
                    if (sqlInfo.getResultType() != null) {
                        String resultType = getSimpleTypeName(sqlInfo.getResultType());
                        sb.append(resultType).append(" result = ").append(varName)
                          .append(".").append(sqlInfo.getId()).append("();\n\n");
                    } else {
                        sb.append("Object result = ").append(varName)
                          .append(".").append(sqlInfo.getId()).append("();\n\n");
                    }
                } else {
                    sb.append("int affected = ").append(varName)
                      .append(".").append(sqlInfo.getId()).append("();\n\n");
                }
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * 获取简化的类型名称
     */
    private static String getSimpleTypeName(String fullTypeName) {
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
     * 主方法，用于测试
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请提供XML文件路径或目录路径");
            return;
        }

        String path = args[0];
        File file = new File(path);

        if (file.isDirectory()) {
            List<MapperInfo> infoList = parseDirectory(path);
            System.out.println("共解析到 " + infoList.size() + " 个Mapper文件");

            for (MapperInfo info : infoList) {
                System.out.println("\n命名空间: " + info.getNamespace());
                for (SqlInfo sqlInfo : info.getSqlInfoList()) {
                    System.out.println("  - " + sqlInfo.getType() + ": " + sqlInfo.getId());
                    System.out.println("    完整方法路径: " + getFullMethodPath(info.getNamespace(), sqlInfo.getId()));
                }
            }

            // 生成Java示例代码
            String javaCode = generateJavaExample(infoList);
            System.out.println("\n生成的Java示例代码:");
            System.out.println(javaCode);

        } else if (file.isFile()) {
            MapperInfo info = parseXml(path);
            System.out.println("命名空间: " + info.getNamespace());
            for (SqlInfo sqlInfo : info.getSqlInfoList()) {
                System.out.println("  - " + sqlInfo.getType() + ": " + sqlInfo.getId());
                System.out.println("    完整方法路径: " + getFullMethodPath(info.getNamespace(), sqlInfo.getId()));
                if (sqlInfo.getResultType() != null) {
                    System.out.println("    返回类型: " + sqlInfo.getResultType());
                }
                if (sqlInfo.getParameterType() != null) {
                    System.out.println("    参数类型: " + sqlInfo.getParameterType());
                }
            }
        } else {
            System.out.println("指定的路径不存在");
        }
    }

    /**
     * Mapper信息类
     */
    public static class MapperInfo {
        private String namespace;
        private List<SqlInfo> sqlInfoList = new ArrayList<>();

        public String getNamespace() {
            return namespace;
        }

        public void setNamespace(String namespace) {
            this.namespace = namespace;
        }

        public List<SqlInfo> getSqlInfoList() {
            return sqlInfoList;
        }

        public void addSqlInfo(SqlInfo sqlInfo) {
            this.sqlInfoList.add(sqlInfo);
        }
    }

    /**
     * SQL信息类
     */
    public static class SqlInfo {
        private String id;
        private String type;
        private String resultType;
        private String parameterType;
        private String sqlContent;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
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

        public String getFullMethodPath(String namespace) {
            return namespace + "." + id;
        }
    }
}
