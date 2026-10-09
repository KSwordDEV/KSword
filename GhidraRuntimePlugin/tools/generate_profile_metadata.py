from pathlib import Path
import json

repo = Path(__file__).resolve().parents[2]
plugin = repo / 'GhidraRuntimePlugin'
payload = repo / '.codex-tmp' / 'decompiler-runtime'
ghidra = payload / 'ghidra_12.0.4_PUBLIC'
ghidra_notice = (repo/'third_party/ghidra_headless/UPSTREAM-NOTICE.txt').read_text(encoding='utf-8')
jdk = payload / 'jdk-21.0.12.1+1'
plugin.mkdir(exist_ok=True)

intro = '''Ghidra runtime backend for KSword

This package contains independently licensed upstream runtimes. Ghidra,
Eclipse Temurin and their third-party components retain their original terms.
The KSword Community Source License does not replace or restrict those rights.

The original KSword profile, installer glue and package metadata are governed
by the unchanged repository KSword Community Source License 1.6, preserved as
KSword-LICENSE.txt. They do not relicense the runtime payloads.

The full principal upstream licenses follow. Additional component licenses
remain in runtime/ghidra_12.0.4_PUBLIC/licenses/ and module LICENSE.txt files,
and jdk/jdk-21.0.12.1+1/legal/. No notice is removed from either runtime.

'''
license_text = intro + '\n=== Ghidra: original Apache License 2.0 ===\n\n' + (ghidra / 'LICENSE').read_text(encoding='utf-8')
license_text += '\n\n=== Temurin: original GPL v2 with Classpath Exception ===\n\n' + (jdk / 'legal/java.base/LICENSE').read_text(encoding='utf-8')
license_text += '\n\n=== Temurin: original additional licensing information ===\n\n' + (jdk / 'legal/java.base/ADDITIONAL_LICENSE_INFO').read_text(encoding='utf-8')
license_text += '\n\n=== Temurin: original project notice ===\n\n' + (jdk / 'NOTICE').read_text(encoding='utf-8')
notice_text = '''# Ghidra runtime backend package

Ghidra 12.0.4: National Security Agency and upstream contributors.
Eclipse Temurin 21.0.12.1+1-LTS: Eclipse Adoptium, OpenJDK and component authors.
This package is independently installable as plugin/ghidra/. The KSword host
uses public APIs in a separate JVM process. Samples are not executed.

Original KSword metadata/profile/installer glue remains under the unchanged
KSword Community Source License 1.6 (KSword-LICENSE.txt). The host's license
does not cover or restrict the independently licensed runtime payloads.

The exact upstream archives are installed without file removal or modification.
Ghidra LICENSE, licenses/, GPL/, every module LICENSE.txt/Module.manifest,
Temurin NOTICE, release, legal/ and lib/src.zip remain present. The source
repository's original Ghidra NOTICE is additionally retained as
UPSTREAM-GHIDRA-NOTICE.txt because the official binary ZIP omits that file.

Principal upstream terms are reproduced in LICENSE.txt. All component notices
in the runtime trees remain controlling for their respective components.

Pinned upstream releases:
- https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.0.4_build
- https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1

Temurin source provenance (from the original release file):
- SOURCE_REPO=https://github.com/adoptium/jdk21u.git
- SOURCE=git:1c417fbfc2f7
- Source tag: https://github.com/adoptium/jdk21u/tree/jdk-21.0.12.1%2B1
- BUILD_SOURCE_REPO=https://github.com/adoptium/temurin-build.git
- BUILD_SOURCE=git:e6ba7dec3d07654074559310376a3ae89da5f4ac
- Build sources: https://github.com/adoptium/temurin-build/tree/e6ba7dec3d07654074559310376a3ae89da5f4ac

The application installer fetches these archives directly from their official
publishers for the user's private installation. It does not mirror them or
publish a new binary distribution. A distributor who later republishes a
combined binary package must also satisfy each component's source-provision
obligations, including complete matching JDK/HotSpot sources and build scripts.
lib/src.zip contains Java sources and is not the complete native JVM source.

=== Original Ghidra NOTICE ===

'''+ghidra_notice+'\n\n=== Original Temurin NOTICE ===\n\n'+(jdk/'NOTICE').read_text(encoding='utf-8')
manifest = {
    'ksword_plugin_api': '1', 'id': 'ghidra', 'name': 'Ghidra C decompiler', 'version': '12.0.4',
    'description': 'Independent Ghidra headless decompiler runtime with its pinned Temurin JDK. Supplies C pseudocode to the shared byte editor without a separate UI tab.',
    'plugin_type': 'backend', 'runtime': 'ghidra', 'targets': ['decompiler'],
    'runtime_root': 'runtime/ghidra_12.0.4_PUBLIC', 'java_executable': 'jdk/jdk-21.0.12.1+1/bin/java.exe',
    'license': 'LICENSE.txt', 'notice': 'NOTICE.md'
}
assets = {'schema_version': 1, 'id': 'ghidra', 'platform': 'windows-x64', 'assets': [
    {'name':'Ghidra 12.0.4','url':'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip','sha256':'c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120','root_directory':'ghidra_12.0.4_PUBLIC','destination_directory':'runtime','max_archive_bytes':1024*1024*1024},
    {'name':'Eclipse Temurin 21.0.12.1+1 x64','url':'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip','sha256':'f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e','root_directory':'jdk-21.0.12.1+1','destination_directory':'jdk','max_archive_bytes':512*1024*1024}
]}
for name,text in [('LICENSE.txt',license_text),('NOTICE.md',notice_text)]:
    (plugin/name).write_text(text, encoding='utf-8', newline='\n')
(plugin/'KSword-LICENSE.txt').write_bytes((repo/'LICENSE').read_bytes())
(plugin/'UPSTREAM-GHIDRA-NOTICE.txt').write_bytes((repo/'third_party/ghidra_headless/UPSTREAM-NOTICE.txt').read_bytes())
for name,data in [('plugin.json',manifest),('runtime-assets.json',assets)]:
    (plugin/name).write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')

wrapper=(repo/'LICENSE').read_text(encoding='utf-8')
parts=['// Original KSword metadata glue. Principal upstream terms are data, not relicensed code.\n']
def utf8_chunks(text, maximum=10000):
    start=0
    size=0
    for index, char in enumerate(text):
        length=len(char.encode('utf-8'))
        if size+length > maximum:
            yield text[start:index]
            start=index
            size=0
        size+=length
    if start<len(text): yield text[start:]


def emit_bytes(function, identifier, text, restore_crlf=False):
    names=[]
    for index, chunk in enumerate(utf8_chunks(text)):
        delimiter=f'KS_{identifier}{index}'
        assert len(delimiter)<=16 and ')'+delimiter+'"' not in chunk
        assert len(chunk.encode('utf-8'))<=10000
        name=f'GhidraRuntimePlugin{identifier}{index}'
        names.append(name)
        parts.append(f'static constexpr const char {name}[] = R"{delimiter}({chunk}){delimiter}";\n')
    parts.append(f'static QByteArray {function}()\n{{\n    QByteArray bytes;\n')
    for name in names: parts.append(f'    bytes.append({name});\n')
    if restore_crlf: parts.append('    bytes.replace("\\n", "\\r\\n");\n')
    parts.append('    return bytes;\n}\n')


emit_bytes('payloadLicenseBytes','PAY',license_text)
emit_bytes('runtimeNoticeBytes','NOTICE',notice_text)
emit_bytes('runtimeUpstreamNoticeBytes','UP',ghidra_notice)
wrapper_source_bytes = (repo/'LICENSE').read_bytes()
restore_crlf=b'\r\n' in wrapper_source_bytes and wrapper_source_bytes.replace(b'\r\n',b'').find(b'\n')<0
emit_bytes('wrapperLicenseBytes','WRAP',wrapper,restore_crlf)
(plugin/'RuntimeLicense.inc').write_text(''.join(parts),encoding='utf-8',newline='\n')
print(f'PROFILE_GENERATED=PASS payload_license_bytes={len(license_text.encode())} wrapper_bytes={len(wrapper.encode())}')
