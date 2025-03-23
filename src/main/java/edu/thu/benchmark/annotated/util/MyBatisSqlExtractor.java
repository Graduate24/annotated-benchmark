package edu.thu.benchmark.annotated.util;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MyBatis XML SQL提取器
 * 用于提取MyBatis XML文件中的namespace和各种SQL ID，并拼接成完整方法路径
 */
public class MyBatisSqlExtractor {

    private static final String[] SQL_TYPES = {"select", "insert", "update", "delete"};

    /**
     * 从单个XML文件中提取方法路径
     *
     * @param xmlFile MyBatis XML文件
     * @return 提取的方法路径列表
     */
    public static List<String> extractMethodPaths(File xmlFile) {
        List<String> methodPaths = new ArrayList<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // 允许DTD处理但禁止外部实体解析和网络访问
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(xmlFile);

            // 提取namespace
            Element mapperElement = document.getDocumentElement();
            String namespace = mapperElement.getAttribute("namespace");

            // 提取各种SQL类型的ID
            for (String sqlType : SQL_TYPES) {
                NodeList sqlNodes = document.getElementsByTagName(sqlType);
                for (int i = 0; i < sqlNodes.getLength(); i++) {
                    Element sqlElement = (Element) sqlNodes.item(i);
                    String id = sqlElement.getAttribute("id");
                    if (id != null && !id.isEmpty()) {
                        String methodPath = namespace + "." + id;
                        methodPaths.add(methodPath);
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("提取" + xmlFile.getName() + "文件时出错: " + e.getMessage());
            e.printStackTrace();
        }

        return methodPaths;
    }

    /**
     * 从目录中提取所有XML文件的方法路径
     *
     * @param directory 包含MyBatis XML文件的目录
     * @return 映射表: XML文件名 -> 方法路径列表
     */
    public static Map<String, List<String>> extractMethodPathsFromDirectory(File directory) {
        Map<String, List<String>> result = new HashMap<>();

        if (!directory.isDirectory()) {
            System.err.println(directory.getAbsolutePath() + "不是一个目录");
            return result;
        }

        File[] xmlFiles = directory.listFiles((dir, name) -> name.toLowerCase().endsWith(".xml"));
        if (xmlFiles == null || xmlFiles.length == 0) {
            System.out.println("目录" + directory.getAbsolutePath() + "中没有XML文件");
            return result;
        }

        for (File xmlFile : xmlFiles) {
            List<String> methodPaths = extractMethodPaths(xmlFile);
            result.put(xmlFile.getName(), methodPaths);
        }

        return result;
    }

    /**
     * 生成方法调用代码
     *
     * @param methodPath 方法路径
     * @return 生成的方法调用代码
     */
    public static String generateMethodCall(String methodPath) {
        int lastDotIndex = methodPath.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return "// 无效的方法路径: " + methodPath;
        }

        String mapperVar = convertToVariableName(methodPath.substring(0, lastDotIndex));
        String methodName = methodPath.substring(lastDotIndex + 1);

        return mapperVar + "." + methodName + "();";
    }

    /**
     * 将类名转换为变量名
     *
     * @param className 类名
     * @return 变量名
     */
    private static String convertToVariableName(String className) {
        if (className == null || className.isEmpty()) {
            return "mapper";
        }

        int lastDotIndex = className.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return className.substring(0, 1).toLowerCase() + className.substring(1);
        }

        String simpleName = className.substring(lastDotIndex + 1);
        return simpleName.substring(0, 1).toLowerCase() + simpleName.substring(1);
    }

    /**
     * 主方法示例
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请提供MyBatis XML文件或目录路径");
            return;
        }

        File input = new File(args[0]);
        if (input.isDirectory()) {
            Map<String, List<String>> result = extractMethodPathsFromDirectory(input);
            System.out.println("\n汇总结果:");
            for (Map.Entry<String, List<String>> entry : result.entrySet()) {
                System.out.println("\n文件: " + entry.getKey());
                for (String methodPath : entry.getValue()) {
                    System.out.println("  " + methodPath);
                    System.out.println("  示例调用: " + generateMethodCall(methodPath));
                }
            }
        } else if (input.isFile() && input.getName().toLowerCase().endsWith(".xml")) {
            List<String> methodPaths = extractMethodPaths(input);
            System.out.println("\n文件: " + input.getName() + " 中提取的方法路径:");
            for (String methodPath : methodPaths) {
                System.out.println("  " + methodPath);
                System.out.println("  示例调用: " + generateMethodCall(methodPath));
            }
        } else {
            System.out.println("提供的路径不是有效的XML文件或目录");
        }
    }
}
