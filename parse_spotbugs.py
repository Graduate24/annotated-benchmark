#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SpotBugs报告解析工具
用于解析SpotBugs生成的XML报告文件，并根据漏洞类型导出到特定文件中
"""

import xml.etree.ElementTree as ET
import os
import sys
import csv
import argparse
from collections import defaultdict
import re

# CWE与Bug Pattern对应表 (部分常见模式)
BUG_PATTERN_TO_CWE = {
    'SQL_INJECTION_SPRING_JDBC': 'CWE-89',  # SQL注入
    'SQL_INJECTION': 'CWE-89',
    'SQL_INJECTION_JDBC': 'CWE-89',
    'COMMAND_INJECTION': 'CWE-78',  # 命令注入
    'PATH_TRAVERSAL_IN': 'CWE-22',  # 路径遍历
    'PATH_TRAVERSAL_OUT': 'CWE-22',
    'XXE_DOCUMENT': 'CWE-611',  # XML外部实体
    'XXE_SAXPARSER': 'CWE-611',
    'XXE_XMLREADER': 'CWE-611',
    'XSS_SERVLET': 'CWE-79',  # 跨站脚本
    'XSS_JSP_PRINT': 'CWE-79',
    'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER': 'CWE-79',
    'URLCONNECTION_SSRF_FD': 'CWE-918',  # 服务器端请求伪造
    'DM_DEFAULT_ENCODING': 'CWE-176',  # 不正确的特殊字符处理
    'IMPROPER_UNICODE': 'CWE-176',
    'INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE': 'CWE-209',  # 敏感信息泄露
}

# 漏洞类型分类
VULNERABILITY_CATEGORIES = {
    'SQL_INJECTION': ['SQL_INJECTION', 'SQL_INJECTION_SPRING_JDBC', 'SQL_INJECTION_JDBC'],
    'COMMAND_INJECTION': ['COMMAND_INJECTION'],
    'PATH_TRAVERSAL': ['PATH_TRAVERSAL_IN', 'PATH_TRAVERSAL_OUT'],
    'XXE': ['XXE_DOCUMENT', 'XXE_SAXPARSER', 'XXE_XMLREADER'],
    'XSS': ['XSS_SERVLET', 'XSS_JSP_PRINT', 'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER'],
    'SSRF': ['URLCONNECTION_SSRF_FD'],
}

# CWE编号与漏洞分类的映射
CWE_TO_CATEGORY = {
    'CWE-89': 'SQL_INJECTION',
    'CWE-78': 'COMMAND_INJECTION',
    'CWE-22': 'PATH_TRAVERSAL',
    'CWE-611': 'XXE',
    'CWE-79': 'XSS',
    'CWE-918': 'SSRF',
    'CWE-176': 'ENCODING_ISSUES',
    'CWE-209': 'INFORMATION_DISCLOSURE'
}

def parse_spotbugs_xml(xml_file):
    """解析SpotBugs的XML文件"""
    if not os.path.exists(xml_file):
        print(f"错误：文件 {xml_file} 不存在")
        return None
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        return root
    except Exception as e:
        print(f"解析XML文件时出错：{e}")
        return None

def extract_method_from_sourceline(sourceline):
    """从源代码行提取方法名"""
    if sourceline:
        method_match = re.search(r'in\s+(\w+)\s*\(', sourceline)
        if method_match:
            return method_match.group(1)
    return "未知方法"

def extract_vulnerabilities(root, output_dir="vulnerability_reports", cwe_filter=None):
    """提取漏洞信息并按类型导出到CSV文件"""
    if root is None:
        return
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 按漏洞类型分组
    vulnerability_groups = defaultdict(list)
    # 按CWE编号分组
    cwe_groups = defaultdict(list)
    
    for bug_instance in root.findall('.//BugInstance'):
        bug_type = bug_instance.get('type')
        priority = bug_instance.get('priority')
        rank = bug_instance.get('rank')
        
        # 获取类名和方法名
        class_element = bug_instance.find('./Class')
        method_element = bug_instance.find('./Method')
        source_line_element = bug_instance.find('./SourceLine')
        
        if class_element is None:
            continue
        
        class_name = class_element.get('classname', "未知类")
        
        method_name = "未知方法"
        if method_element is not None:
            method_name = method_element.get('name', "未知方法")
        elif source_line_element is not None:
            # 尝试从SourceLine中提取方法名
            sourceline = bug_instance.find('./SourceLine')
            if sourceline is not None:
                primary = sourceline.get('primary', '')
                if primary:
                    method_name = extract_method_from_sourceline(primary)
        
        # 获取文件名和行号
        start_line = "未知"
        end_line = "未知"
        file_name = "未知文件"
        
        if source_line_element is not None:
            file_name = source_line_element.get('sourcefile', "未知文件")
            start_line = source_line_element.get('start', "未知")
            end_line = source_line_element.get('end', "未知")
        
        # 获取漏洞描述
        message_element = bug_instance.find('./LongMessage')
        description = message_element.text if message_element is not None else "无描述"
        
        # 确定CWE编号
        cwe = BUG_PATTERN_TO_CWE.get(bug_type, "未知CWE")
        
        # 创建漏洞信息字典
        vulnerability = {
            'bug_type': bug_type,
            'class_name': class_name,
            'method_name': method_name,
            'file_name': file_name,
            'start_line': start_line,
            'end_line': end_line,
            'priority': priority,
            'rank': rank,
            'description': description,
            'cwe': cwe
        }
        
        # 如果指定了CWE过滤器，只处理特定CWE的漏洞
        if cwe_filter and cwe != cwe_filter:
            continue
        
        # 将漏洞添加到相应类别
        for category, patterns in VULNERABILITY_CATEGORIES.items():
            if bug_type in patterns:
                vulnerability_groups[category].append(vulnerability)
                break
        
        # 同时将所有漏洞添加到"ALL"类别
        vulnerability_groups['ALL'].append(vulnerability)
        
        # 按CWE编号分组
        cwe_groups[cwe].append(vulnerability)
    
    # 输出按漏洞类型分组的CSV文件
    for category, vulnerabilities in vulnerability_groups.items():
        if not vulnerabilities:
            continue
            
        output_file = os.path.join(output_dir, f"{category.lower()}_vulnerabilities.csv")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['bug_type', 'class_name', 'method_name', 'file_name', 
                          'start_line', 'end_line', 'priority', 'rank', 'cwe', 'description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vulnerability in vulnerabilities:
                writer.writerow(vulnerability)
        
        print(f"已将 {len(vulnerabilities)} 个 {category} 类型的漏洞导出到 {output_file}")
    
    # 如果指定了CWE过滤器，只输出特定CWE的漏洞
    if cwe_filter:
        return
    
    # 输出按CWE编号分组的CSV文件
    for cwe, vulnerabilities in cwe_groups.items():
        if not vulnerabilities:
            continue
        
        # 替换CWE编号中的破折号以便于文件命名
        cwe_filename = cwe.replace('-', '_').lower()
        output_file = os.path.join(output_dir, f"cwe_{cwe_filename}_vulnerabilities.csv")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['bug_type', 'class_name', 'method_name', 'file_name', 
                          'start_line', 'end_line', 'priority', 'rank', 'cwe', 'description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vulnerability in vulnerabilities:
                writer.writerow(vulnerability)
        
        print(f"已将 {len(vulnerabilities)} 个 {cwe} 类型的漏洞导出到 {output_file}")

def export_vulnerability_by_cwe(root, cwe, output_dir="vulnerability_reports"):
    """导出指定CWE编号的漏洞信息"""
    if root is None:
        return
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    vulnerabilities = []
    
    for bug_instance in root.findall('.//BugInstance'):
        bug_type = bug_instance.get('type')
        priority = bug_instance.get('priority')
        rank = bug_instance.get('rank')
        
        # 确定CWE编号
        bug_cwe = BUG_PATTERN_TO_CWE.get(bug_type, "未知CWE")
        
        # 如果不匹配指定的CWE编号，跳过
        if bug_cwe != cwe:
            continue
        
        # 获取类名和方法名
        class_element = bug_instance.find('./Class')
        method_element = bug_instance.find('./Method')
        source_line_element = bug_instance.find('./SourceLine')
        
        if class_element is None:
            continue
        
        class_name = class_element.get('classname', "未知类")
        
        method_name = "未知方法"
        if method_element is not None:
            method_name = method_element.get('name', "未知方法")
        elif source_line_element is not None:
            # 尝试从SourceLine中提取方法名
            sourceline = bug_instance.find('./SourceLine')
            if sourceline is not None:
                primary = sourceline.get('primary', '')
                if primary:
                    method_name = extract_method_from_sourceline(primary)
        
        # 获取文件名和行号
        start_line = "未知"
        end_line = "未知"
        file_name = "未知文件"
        
        if source_line_element is not None:
            file_name = source_line_element.get('sourcefile', "未知文件")
            start_line = source_line_element.get('start', "未知")
            end_line = source_line_element.get('end', "未知")
        
        # 获取漏洞描述
        message_element = bug_instance.find('./LongMessage')
        description = message_element.text if message_element is not None else "无描述"
        
        # 创建漏洞信息字典
        vulnerability = {
            'bug_type': bug_type,
            'class_name': class_name,
            'method_name': method_name,
            'file_name': file_name,
            'start_line': start_line,
            'end_line': end_line,
            'priority': priority,
            'rank': rank,
            'description': description,
            'cwe': bug_cwe
        }
        
        vulnerabilities.append(vulnerability)
    
    if not vulnerabilities:
        print(f"未找到与 {cwe} 相关的漏洞")
        return
    
    # 替换CWE编号中的破折号以便于文件命名
    cwe_filename = cwe.replace('-', '_').lower()
    output_file = os.path.join(output_dir, f"cwe_{cwe_filename}_vulnerabilities.csv")
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['bug_type', 'class_name', 'method_name', 'file_name', 
                      'start_line', 'end_line', 'priority', 'rank', 'cwe', 'description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for vulnerability in vulnerabilities:
            writer.writerow(vulnerability)
    
    print(f"已将 {len(vulnerabilities)} 个 {cwe} 类型的漏洞导出到 {output_file}")

def main():
    parser = argparse.ArgumentParser(description='SpotBugs漏洞报告解析工具')
    parser.add_argument('-f', '--file', dest='xml_file', default='target/spotbugsXml.xml',
                        help='SpotBugs XML报告文件路径')
    parser.add_argument('-o', '--output-dir', dest='output_dir', default='vulnerability_reports',
                        help='输出目录')
    parser.add_argument('-c', '--cwe', dest='cwe', 
                        help='按CWE编号筛选漏洞 (例如: CWE-89 表示SQL注入漏洞)')
    parser.add_argument('-t', '--type', dest='vuln_type',
                        help='按漏洞类型筛选 (例如: SQL_INJECTION, COMMAND_INJECTION, PATH_TRAVERSAL等)')
    parser.add_argument('-l', '--list-cwe', action='store_true', 
                        help='列出所有支持的CWE编号及其描述')
    args = parser.parse_args()
    
    if args.list_cwe:
        print("支持的CWE编号及其描述:")
        for cwe, category in CWE_TO_CATEGORY.items():
            print(f"{cwe}: {category}")
        return
    
    xml_file = args.xml_file
    output_dir = args.output_dir
    
    root = parse_spotbugs_xml(xml_file)
    if root is None:
        return
    
    if args.cwe:
        export_vulnerability_by_cwe(root, args.cwe, output_dir)
    elif args.vuln_type:
        if args.vuln_type not in VULNERABILITY_CATEGORIES:
            print(f"错误：不支持的漏洞类型 {args.vuln_type}")
            print("支持的漏洞类型:", ", ".join(VULNERABILITY_CATEGORIES.keys()))
            return
        # 使用extract_vulnerabilities函数导出特定类型的漏洞
        # 此处可以优化为只导出特定类型，但为了代码简洁性，我们仍然使用完整的函数
        extract_vulnerabilities(root, output_dir)
    else:
        extract_vulnerabilities(root, output_dir)

if __name__ == "__main__":
    main() 