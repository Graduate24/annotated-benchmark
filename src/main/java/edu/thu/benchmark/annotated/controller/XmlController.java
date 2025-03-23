package edu.thu.benchmark.annotated.controller;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/xml")
public class XmlController {

    @GetMapping
    public String xmlPage() {
        return "xml";
    }

    @Vulnerability(
            type = VulnerabilityType.XXE,
            cwe = 611,
            description = "此方法存在XML外部实体(XXE)注入漏洞，允许攻击者读取服务器上的敏感文件",
            remediation = "禁用XML处理器中的外部实体解析，设置'feature'标志，如XMLConstants.FEATURE_SECURE_PROCESSING",
            level = VulnerabilityLevel.CRITICAL,
            isRealVulnerability = true
    )
    @PostMapping("/parse")
    @ResponseBody
    public Map<String, Object> parseXml(@RequestParam String xml) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 不安全的XML解析 - 没有禁用外部实体
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            // 使用StringReader和InputSource解析XML
            StringReader reader = new StringReader(xml);
            InputSource source = new InputSource(reader);
            Document document = builder.parse(source);

            // 处理解析结果
            Element rootElement = document.getDocumentElement();
            response.put("rootName", rootElement.getNodeName());

            // 获取并处理所有user元素
            NodeList userList = rootElement.getElementsByTagName("user");
            String[] usernames = new String[userList.getLength()];

            for (int i = 0; i < userList.getLength(); i++) {
                Element userElement = (Element) userList.item(i);
                usernames[i] = userElement.getElementsByTagName("name").item(0).getTextContent();
            }

            response.put("users", usernames);
            response.put("success", true);
            response.put("message", "XML解析成功");

        } catch (ParserConfigurationException | SAXException | IOException e) {
            response.put("success", false);
            response.put("message", "XML解析失败: " + e.getMessage());
        }

        return response;
    }

    @PostMapping("/parse-safe")
    @ResponseBody
    public Map<String, Object> parseXmlSafe(@RequestParam String xml) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 安全的XML解析 - 禁用外部实体
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // 禁用外部实体处理
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();

            // 使用StringReader和InputSource解析XML
            StringReader reader = new StringReader(xml);
            InputSource source = new InputSource(reader);
            Document document = builder.parse(source);

            // 处理解析结果
            Element rootElement = document.getDocumentElement();
            response.put("rootName", rootElement.getNodeName());

            // 获取并处理所有user元素
            NodeList userList = rootElement.getElementsByTagName("user");
            String[] usernames = new String[userList.getLength()];

            for (int i = 0; i < userList.getLength(); i++) {
                Element userElement = (Element) userList.item(i);
                usernames[i] = userElement.getElementsByTagName("name").item(0).getTextContent();
            }

            response.put("users", usernames);
            response.put("success", true);
            response.put("message", "XML安全解析成功");

        } catch (ParserConfigurationException | SAXException | IOException e) {
            response.put("success", false);
            response.put("message", "XML解析失败: " + e.getMessage());
        }

        return response;
    }

    @Vulnerability(
            type = VulnerabilityType.XXE,
            cwe = 611,
            description = "此方法存在XML外部实体(XXE)注入漏洞，允许攻击者包含外部DTD",
            remediation = "禁用XML处理器中的外部DTD处理",
            level = VulnerabilityLevel.HIGH,
            isRealVulnerability = true
    )
    @PostMapping("/process")
    @ResponseBody
    public Map<String, Object> processXml(@RequestBody String xmlContent) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 另一种不安全的XML解析方式
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // 危险：显式启用DTD处理
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xmlContent)));

            // 处理解析结果
            Element rootElement = document.getDocumentElement();
            response.put("rootElement", rootElement.getNodeName());
            response.put("success", true);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        return response;
    }
}
