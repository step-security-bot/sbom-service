# 背景

在美国2021年颁布的《关于改善国家网络安全的行政命令》14028号行政令中，特别要求政府软件应包含机器可读的软件物料清单(Software Bill Of Materials, SBOM)。NTIA基于14028号行政命令的要求，所公布的的SBOM最小集主要包含三个领域：数据字段（Data Fields）、自动化工具支持（Automation Support）、实践及流程（Practices and Processes）。这三个维度用于推动数据获取技术和手段的不断发展，从而最终提升软件供应链透明度。

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

---

[返回目录](../../README.md)
