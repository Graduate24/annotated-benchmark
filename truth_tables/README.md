# 漏洞真值表说明

本目录包含不同类型漏洞的真值表，用于标记代码中的漏洞位置以及相应的修复方法。

## 文件格式

所有真值表采用CSV格式，包含以下列：

- `file_path`: 文件路径
- `class_name`: 类名
- `method_name`: 方法名
- `start_line`: 漏洞代码开始行
- `end_line`: 漏洞代码结束行
- `is_vulnerability`: 是否为真实漏洞（true/false）
- `vulnerability_description`: 漏洞描述
- `remediation`: 修复建议

## 包含的真值表

1. `sql_injection_cwe89.csv` - SQL注入漏洞 (CWE-89)
   - 包含42个测试用例（21个正例，21个负例）
   - 涵盖MyBatis、原生JDBC、String拼接等场景下的SQL注入漏洞
   
2. `path_traversal_cwe22.csv` - 路径遍历漏洞 (CWE-22)
   - 包含20个测试用例（10个正例，10个负例）
   - 涵盖文件操作、资源加载、压缩文件处理等场景下的路径遍历漏洞
   - 包含依赖注入和AOP相关的案例

3. `command_injection_cwe78.csv` - 命令注入漏洞 (CWE-78)
   - 包含20个测试用例（10个正例，10个负例）
   - 涵盖直接命令执行、ProcessBuilder使用、Runtime.exec等场景下的命令注入漏洞
   - 包含依赖注入、AOP切面和配置文件读取等相关案例

## 使用方法

这些真值表可用于：

1. 标记代码中的安全漏洞
2. 评估静态代码分析工具的检测效果
3. 作为安全代码审计的参考
4. 指导代码修复和安全编码实践 