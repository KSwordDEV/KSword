#!/usr/bin/env python3
"""直接运行本脚本，校验本批六份工程 XML、源码登记和路径；失败返回 1，否则返回 0。"""
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # 从固定验证目录定位仓库根，不使用当前 shell 目录。
FILES = [  # 本批涉及的产品及原生验证工程与 filters。
    'Ksword5.1/Ksword5.1/Ksword5.1.vcxproj',
    'Ksword5.1/Ksword5.1/Ksword5.1.vcxproj.filters',
    'KswordARKLight/KswordARKLight.vcxproj',
    'KswordARKLight/KswordARKLight.vcxproj.filters',
    'KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj',
    'KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj.filters',
]
NEED = {  # 每份工程必须登记的源码与共享头；只检查本批接线，不替其它作者整改工程。
    'Ksword5.1/Ksword5.1/Ksword5.1.vcxproj': [
        r'ActionAnalyze\ApiTransferPresentation.cpp',
        r'ActionAnalyze\ApiTransferPresentation.h',
        r'..\..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.cpp',
        r'..\..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.h',
        r'..\..\shared\evidence\ApiTransferCandidateWindow.h',
    ],
    'Ksword5.1/Ksword5.1/Ksword5.1.vcxproj.filters': [
        r'ActionAnalyze\ApiTransferPresentation.cpp',
        r'ActionAnalyze\ApiTransferPresentation.h',
        r'..\..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.cpp',
        r'..\..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.h',
        r'..\..\shared\evidence\ApiTransferCandidateWindow.h',
    ],
    'KswordARKLight/KswordARKLight.vcxproj': [
        r'Features\ActionAnalyze\ApiTransferCandidateTree.cpp',
        r'Features\ActionAnalyze\ApiTransferCandidateTree.h',
        r'Features\ActionAnalyze\ApiTransferPresentation.cpp',
        r'Features\ActionAnalyze\ApiTransferPresentation.h',
        r'..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.cpp',
        r'..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.h',
        r'..\shared\evidence\ApiTransferCandidateWindow.h',
    ],
    'KswordARKLight/KswordARKLight.vcxproj.filters': [
        r'Features\ActionAnalyze\ApiTransferCandidateTree.cpp',
        r'Features\ActionAnalyze\ApiTransferCandidateTree.h',
        r'Features\ActionAnalyze\ApiTransferPresentation.cpp',
        r'Features\ActionAnalyze\ApiTransferPresentation.h',
        r'..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.cpp',
        r'..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.h',
        r'..\shared\evidence\ApiTransferCandidateWindow.h',
    ],
    'KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj': [
        r'..\..\..\..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.cpp',
        r'..\..\..\..\shared\evidence\ApiTransferCandidateWindow.h',
    ],
    'KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj.filters': [
        r'..\..\..\..\KswordCLI\ActionAnalyze\Detection\ApiTransferChain.cpp',
        r'..\..\..\..\shared\evidence\ApiTransferCandidateWindow.h',
    ],
}

errors = []  # 汇总全部登记、XML 和路径错误后一次性回报。
# 每份工程分别解析，再按它自身目录解析相对路径；不调用构建工具。
for rel in FILES:
    path = ROOT / rel  # 当前被检查的实际工程文件。
    if not path.exists():
        errors.append(f'MISSING_FILE {rel}')
        continue
    try:
        tree = ET.parse(path)  # XML 解析失败与缺少登记分开报告。
    except ET.ParseError as exc:
        errors.append(f'BAD_XML {rel}: {exc}')
        continue
    includes = {el.get('Include') for el in tree.iter()  # 工程或 filters 中的编译项与头文件项。
                if el.tag.rsplit('}', 1)[-1] in ('ClCompile', 'ClInclude')}
    for wanted in NEED.get(rel, []):
        if wanted not in includes:
            errors.append(f'NOT_REGISTERED {rel}: {wanted}')
        target = (path.parent / wanted.replace('\\', '/')).resolve()  # 登记项对应的绝对源码路径。
        if not target.exists():
            errors.append(f'DEAD_PATH {rel}: {wanted} -> {target}')
    print(f'CHECKED {rel}: {len(includes)} includes')

# 输出完整问题清单，供 CodeBuddy 回执记录；没有文件修改或运行时副本。
print(f'RESULT errors={len(errors)}')
for err in errors:
    print(err)
raise SystemExit(1 if errors else 0)
