# Java漏洞基准测试框架

这个项目提供了一个带注释的Java应用程序基准测试框架，用于评估静态分析工具（特别是SpotBugs）对常见Web安全漏洞的检测能力。

## 支持的漏洞类型

该框架包含以下CWE（Common Weakness Enumeration）漏洞类型的测试用例：

- **CWE-22**: 路径遍历 - 10个正例（易受攻击）和10个反例（安全实现）
- **CWE-78**: 操作系统命令注入 - 10个正例和10个反例
- **CWE-89**: SQL注入 - 21个正例和21个反例

## 使用方法

### 运行基准测试应用程序

```bash
# 编译项目并运行SpotBugs检查
mvn clean compile spotbugs:check

# 运行SpotBugs并启动GUI界面查看结果
mvn spotbugs:spotbugs spotbugs:gui

# 导出SpotBugs结果为XML格式
mvn spotbugs:spotbugs -Dspotbugs.outputFile=spotbugs_results.xml
```

### 评估SpotBugs检测能力

本项目提供了多种工具来评估SpotBugs的漏洞检测能力：

1. **XML解析工具** - 将SpotBugs XML结果转换为JSON格式：
   ```bash
   python3 parse_spotbugs_xml.py -i spotbugs_results.xml -o spotbugs_results.json
   ```
   
2. **基本评估工具** - 对比SpotBugs检测结果与真实情况：
   ```bash
   python3 evaluate_spotbugs.py
   ```

3. **增强版评估工具** - 支持调用链上的漏洞匹配：
   ```bash
   # 生成调用图
   python3 generate_call_graph.py --with-manual
   
   # 使用调用链进行评估
   python3 evaluate_spotbugs_enhanced.py --with-call-graph
   
   # 运行完整的比较测试
   python3 test_call_graph_analysis.py
   ```

请参阅以下文档获取详细使用指南：
- [完整使用指南](USAGE_GUIDE.md) - 从头到尾的详细操作步骤
- [SpotBugs解析工具说明](README_spotbugs_parser.md) - XML解析工具详细说明
- [SpotBugs评估工具说明](README_evaluation.md) - 基本评估脚本详细说明
- [增强版评估工具说明](README_enhanced_evaluation.md) - 支持调用链的评估工具说明
- [评估结果示例](evaluation_summary.md) - 评估报告示例

## 真实情况表（Truth Tables）

项目包含详细的真实情况表，记录了每种漏洞类型的所有测试用例：

- 路径遍历: `truth_tables/path_traversal_cwe22.csv`
- 命令注入: `truth_tables/command_injection_cwe78.csv`
- SQL注入: `truth_tables/sql_injection_cwe89.csv`

## 项目结构

```
.
├── src/ - Java源代码，包含漏洞测试案例
├── truth_tables/ - 漏洞真实情况表（CSV格式）
├── evaluate_spotbugs.py - 基本评估脚本
├── evaluate_spotbugs_enhanced.py - 增强版评估脚本（支持调用链）
├── generate_call_graph.py - 调用图生成工具
├── parse_spotbugs_xml.py - 解析SpotBugs XML结果的脚本
├── test_call_graph_analysis.py - 调用链分析测试脚本
├── example_spotbugs_results.json - 示例SpotBugs结果文件
├── evaluation_summary.md - 评估结果示例报告
├── USAGE_GUIDE.md - 完整使用指南
└── README_enhanced_evaluation.md - 增强版评估工具说明
```

## 调用链分析

本框架的亮点功能是支持调用链分析的漏洞评估，解决了传统评估方法的局限性：

- **问题**：传统评估只考虑直接匹配的方法，而SpotBugs通常在调用链的不同位置检测漏洞
- **解决方案**：通过构建调用图，在评估时考虑整个调用链上的漏洞
- **优势**：更准确地评估静态分析工具的真实性能，减少假阳性和假阴性的统计偏差

## 贡献

欢迎提交Pull Request以添加更多漏洞类型或改进现有测试用例。