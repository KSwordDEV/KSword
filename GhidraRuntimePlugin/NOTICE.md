# Ghidra runtime backend package

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

Ghidra

This product includes software developed at National Security Agency
(https://www.nsa.gov)

Portions of this product were created by the U.S. Government and not subject to
U.S. copyright protections under 17 U.S.C.

The remaining portions are copyright their respective authors and have been
contributed under the terms of one or more open source licenses, and made
available to you under the terms of those licenses. (See LICENSE)



Licensing Intent

The intent is that this software and documentation ("Project") should be treated
as if it is licensed under the license associated with the Project ("License")
in the LICENSE file. However, because we are part of the United States (U.S.)
Federal Government, it is not that simple.

The portions of this Project written by U.S. Federal Government employees within
the scope of their federal employment are ineligible for copyright protection in
the U.S.; this is generally understood to mean that these portions of the
Project are placed in the public domain.

In countries where copyright protection is available (which does not include the
U.S.), contributions made by U.S. Federal Government employees are released
under the License. Merged contributions from private contributors are released
under the License.

The Ghidra software is released under the Apache License, Version 2.0
("Apache 2.0").

In addition, each module may contain numerous 3rd party components (libraries,
icons, etc.) that each have their own license which is compatible with Apache
2.0. Each module has a LICENSE.txt file that lists each license used in that
module and the 3rd party files that fall under that license. The license files
for each license used by Ghidra can be found in the licenses directory at the
installation root.

Also, in the GPL directory, there are several stand-alone support programs that
are released using the GPL 3 license.  Ghidra executes these programs as needed
and parses the output to get the desired results. There is a licenses directory
under the GPL directory that has the GPL license files.

Consistent with the inbound=outbound model, contributions to any module must be
made available, by the contributor, under the applicable license(s). Please read
the Legal section of the CONTRIBUTING.md guide.


=== Original Temurin NOTICE ===

# Notices for Eclipse Temurin

This content is produced and maintained by the Eclipse Temurin project.

 * Project home: https://projects.eclipse.org/projects/adoptium.temurin

## Trademarks

Eclipse Temurin is a trademark of the Eclipse Foundation. Eclipse, and the
Eclipse Logo are registered trademarks of the Eclipse Foundation.

Java and all Java-based trademarks are trademarks of Oracle Corporation in
the United States, other countries, or both.

## Copyright

All content is the property of the respective authors or their employers.
For more information regarding authorship of content, please consult the
listed source code repository logs.

## Declared Project Licenses

This program and the accompanying materials are made available under the terms
of the GNU General Public License, version 2, with the Classpath Exception.

Additional information relating to the program and accompanying materials
license and usage is available as follows.
 * For Eclipse Temurin version 8 see the LICENSE and ASSEMBLY_EXCEPTION files
in the top level directory of the installation.
 * For Eclipse Temurin version 9 or later see the files under the legal/
directory in the top level directory of the installation.

SPDX-License-Identifier: GPL-2.0 WITH Classpath-exception-2.0

## Source Code

The project maintains the following source code repositories which may be
relevant to this content:

 * https://github.com/adoptium/temurin-build
 * https://github.com/adoptium/jdk
 * https://github.com/adoptium/jdk8u
 * https://github.com/adoptium/jdk11u
 * https://github.com/adoptium/jdk17u
 * https://github.com/adoptium/jdk20
 * and so on

## Third-party Content

This program and accompanying materials contains third-party content.
 * For Eclipse Temurin version 8 see the THIRD_PARTY_LICENSE file in the
top level directory of the installation.
 * For Eclipse Temurin version 9 or later see the files under the legal/
directory in the top level directory of the installation.

## Cryptography

Content may contain encryption software. The country in which you are currently
may have restrictions on the import, possession, and use, and/or re-export to
another country, of encryption software. BEFORE using any encryption software,
please check the country's laws, regulations and policies concerning the import,
possession, or use, and re-export of encryption software, to see if this is
permitted.
