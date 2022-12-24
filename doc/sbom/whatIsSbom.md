# 背景

在美国2021年颁布的《关于改善国家网络安全的行政命令》14028号行政令中，特别要求政府软件应包含机器可读的软件物料清单(Software Bill Of Materials, SBOM)。美国国家电信和信息管理局(NITA)在14028号政令的要求下，在2021年7月12日发布了[《SBOM 最小元素集》](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)，该文档为各开发工具的组织和厂商提供了SBOM数据格式的参考。NITA发布的SBOM最小元素集包括：


| 数据字段       | 描述                                                             |
| -------------- | ---------------------------------------------------------------- |
| 供应商名称     | 创建、定义和标识组件的实体的名称。                               |
| 组件名称       | 分配给原始供应商定义的软件单元的名称。                           |
| 组件的版本     | 组件版本号、供应商用来指定软件从先前标识的版本发生变化的标识符。 |
| 其它唯一标识符 | 用于标识组件或用作相关数据库的查找键的其他标识符。               |
| 依赖关系       | 软件依赖关系、表征上游组件 X 包含在软件 Y 中的关系               |
| SBOM数据的作者 | 为此组件创建SBOM数据的实体的名称。                               |
| 时间戳         | 记录SBOM数据组装的日期和时间。                                   |
| **推荐的数据** |                                                                  |
| 组件的哈希     | 组件的唯一哈希，以帮助允许列表或拒绝列表。                       |
| 生命周期阶段   | SDLC 中捕获 SBOM 数据的获取的阶段。                              |

# 什么是SBOM

SBOM是一种正式标准化的、机器可读的元数据;它唯一地标识软件，及其所包含的各种软件组件的详细信息和供应链关系；也可能包括版权和许可证等成分数据。如今主流SBOM标准包括[SPDX](https://spdx.dev/)、[CycloneDX](https://cyclonedx.org/)、[SWID](https://nvd.nist.gov/products/swid)等。

# SBOM的应用场景和价值

SBOM致力于软件安全供应链透明的数据底座、跨组织共享、并贯穿SDLC。

可应用于软件供应链安全管理、安全漏洞管理、安全应急响应，高可信安全应用管理等场景；能帮助软件生产商、购买者和运营商更高效的识别软件成分、排查License风险/合规风险/安全漏洞影响风险、履行义务声明等。未来势必将成为软件的必需交付件之一。

![](https://www.openeuler.org/assets/SBOM.471fa2d1.png)



# 参考

1. [基于SBOM的开源社区软件供应链安全解决方案](https://www.openeuler.org/zh/blog/robell/openEuler_SBOM_Practice.html)
2. [谈谈我对云原生与软件供应链安全的思考](https://developer.aliyun.com/article/1005501?utm_content=m_1000357528)
3. [awesome-sbom](https://github.com/awesomeSBOM/awesome-sbom)
