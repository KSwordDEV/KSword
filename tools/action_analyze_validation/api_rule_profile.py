"""从源码规则库读取桌面夹具所需的展示文案。"""

import json
from pathlib import Path


PROFILE = Path(__file__).resolve().parents[2] / 'Ksword5.1/Ksword5.1/profiles/action_analyze_api_rules.json'


def read_rule_profile():
    """读取源码中的 UTF-8 规则定义；不读取或执行受测程序。"""
    return json.loads(PROFILE.read_text(encoding='utf-8'))


def behavior_rule(rule_id):
    """按夹具独立指定的规则 ID 返回唯一的行为定义。"""
    rule, = (rule for rule in read_rule_profile()['behaviorRules'] if rule['ruleId'] == rule_id)
    return rule


def display_summary(rule):
    """返回中文桌面应显示的释义；未提供中文时读取默认英文。"""
    return rule.get('summaryZh') or rule['summary']
