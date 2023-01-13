# SBOM最小元素集

美国国家电信和信息管理局(NTIA)在14028号政令的要求下，在2021年7月12日发布了[《SBOM 最小元素集》](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)，该文档为各组织和厂商开发SBOM工具提供了数据格式的参考。NTIA发布的SBOM最小元素集包括：


| 数据字段                                      | 描述                                                           |
| --------------------------------------------- | -------------------------------------------------------------- |
| 组件供应商名称（Supplier Name）               | 创建、定义、和标识组件的实体名称。                             |
| 组件名称（Component Name）                    | 原始供应商为软件单元定义的名称。                               |
| 组件版本（Version of the Component）          | 供应商为软件单元定义的版本号。                                 |
| 组件其他唯一标识（Other Unique Identifiers）  | 组件唯一性描述标识符，具备在组件信息库中快速检索能力。         |
| 组件依赖关系（Dependency Relationship）       | 描述软件的依赖关系，例如：上游组件X包含在软件Y中。             |
| SBOM数据作者（Author of SBOM Data）           | 生成SBOM文件的实体名称。                                       |
| SBOM时间戳（Timestamp）                       | SBOM文件生成的时间。                                           |
| **推荐的数据字段**                            |                                                                |
| 组件的哈希（Hash of the Component）           | 组件的哈希值，可用于二进制文件等类型组件的消费场景。           |
| 生命周期阶段（Lifecycle Phase）               | 生成SBOM数据所处的生命周期阶段。                               |
| 其他组件关系（Other Component Relationships） | 用于扩展组件间依赖以外的依赖关系，例如：补丁关系、源码引用等。 |
| 组件License信息（License Information）        | 有助于大型、复杂软件的合规性管理。                             |

# SBOM Service对主流SBOM标准协议的支持

当前SBOM Service根据最小元素集为基础进行了一定的字段扩充，以SBOM元数据形式持久化，解耦于[SPDX](https://spdx.dev/)、[CycloneDX](https://cyclonedx.org/)、[SWID](https://nvd.nist.gov/products/swid)等主流SBOM标准协议。SBOM Service提供SBOM文件导出功能，导出时可以自由选择具体的SBOM协议和文件格式（XML、JSON、YAML）。下表罗列了SBOM Service中当前主要支持的数据字段


| 最小集数据字段         | SPDX                                                                                                                                  | CycloneDX                                                                                                                                                                                                                                                                                        |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **组件供应商名称**     | document->packages->supplier                                                                                                          | document->components->supplier                                                                                                                                                                                                                                                                   |
| **组件名称**        | document->packages->name                                                                                                              | document->components->name                                                                                                                                                                                                                                                                       |
| **组件版本**        | document->packages->versionInfo（openEuler使用了epoch:version-release格式）                                                                  | document->components->version（openEuler使用了epoch:version-release格式）                                                                                                                                                                                                                               |
| **组件其他唯一标识**    | document->packages->externalRefs(category:PACKAGE_MANAGER)->purl                                                                      | document->components->purl                                                                                                                                                                                                                                                                       |
| **组件依赖关系**      | document->packages->externalRefs(category:EXTERNAL_MANAGER)->purl                                                                     | 依赖组件类型：document->components->components(properties->value:EXTERNAL_MANAGER)->type<br />依赖组件名称：document->components->components(properties->value:EXTERNAL_MANAGER)->name<br />依赖组件标识：document->components->components(properties->value:EXTERNAL_MANAGER)->purl                                  |
| **SBOM数据作者**    | document->creationInfo->creators                                                                                                      | document->metadata->manufacture->name                                                                                                                                                                                                                                                            |
| **SBOM时间戳**     | document->creationInfo->created                                                                                                       | document->metadata->timestamp                                                                                                                                                                                                                                                                    |
| *组件的哈希*         | document->packages->checksums                                                                                                         | document->components->hashes                                                                                                                                                                                                                                                                     |
| *生命周期阶段*        | 未支持                                                                                                                                   | 未支持                                                                                                                                                                                                                                                                                              |
| *其他组件关系*        | 内部子组件：document->packages->externalRefs(category:PROVIDE_MANAGER)->purl<br/>运行时依赖：document->relationships(relationshipType:DEPENDS_ON) | 内部子组件类型：document->components->components(properties->value:PROVIDE_MANAGER)->type<br />内部子组件名称：document->components->components(properties->value:PROVIDE_MANAGER)->name<br />内部子组件标识：document->components->components(properties->value:PROVIDE_MANAGER)->purl<br/>运行时依赖：document->dependencies |
| *组件License信息*   | document->packages->licenseDeclared<br />document->packages->licenseConcluded                                                         | document->components->licenses->expression                                                                                                                                                                                                                                                       |
| *组件Copyright信息* | document->packages->copyrightText                                                                                                     | document->components->copyright                                                                                                                                                                                                                                                                  |
| *组件上游社区信息*      | document->packages->externalRefs(category:SOURCE_MANAGER)->url                                                                        | document->components->externalReferences(type:vcs)->url                                                                                                                                                                                                                                          |
| *组件补丁信息*        | 补丁文件：document->files(fileTypes:SOURCE)<br />补丁关系：document->relationships(relationshipType:PATCH_APPLIED)                              | 补丁类型：document->components->pedigree->patches->type<br />补丁文件：document->components->pedigree->patches->diff->url                                                                                                                                                                                  |
| *组件来源*          | document->packages->downloadLocation                                                                                                  | document->components->externalReferences(type:distribution)->url                                                                                                                                                                                                                                 |
| *组件信息*          | document->packages->description<br />document->packages->summary                                                                      | document->components->description<br />document->components->properties(name:summary)->value                                                                                                                                                                                                     |
| *组件官网/博客*       | document->packages->homepage                                                                                                          | document->components->externalReferences(type:website)->url                                                                                                                                                                                                                                      |

备注

1. SBOM服务在“内部子组件”、“组件传递性依赖”、“组件上游社区信息”三个SBOM元数据对SPDX协议的适配中，将document->packages->externalRefs->category字段的可选枚举值做了扩展，新增三个枚举值：PROVIDE_MANAGER、EXTERNAL_MANAGER、SOURCE_MANAGER。

# SBOM与漏洞信息

SBOM服务已实现漏洞数据的卷积，在数据库中独立存储。当前导出时暂时将漏洞数据合在SBOM文件中，SPDX使用数据字段：document->
packages->externalRefs(category:SECURITY)->CVE，CycloneDX使用数据字段：document->vulnerabilities。

SBOM Service正在根据业界主流规范（静态SBOM数据+动态漏洞数据），计划采用SBOM+VEX的方案将SBOM数据和漏洞数据分开生成。

---

[返回目录](../../README.md)
