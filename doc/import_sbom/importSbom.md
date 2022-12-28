# SBOM导入

依托SBOM客户端工具[sbom-generator](https://github.com/opensourceways/sbom-tools/tree/main/sbom-generator)、[sbom-tracer](https://github.com/opensourceways/sbom-tools/tree/main/sbom-tracer)结合CI/CD发布流水线，生成SBOM初始化数据：**原始态的SBOM文件**、**eBPF监控数据**、**高阶语言包管理器配置文件**等。

通过调用SBOM-Service的[数据导入API](https://github.com/opensourceways/sbom-service/blob/main/doc/api/制品发布.md)将SBOM初始化数据上传至服务端，SBOM-Service将会通过导入流程执行：**监控数据解析**、**软件成分分析**、**依赖组件分析**、**SBOM元数据存储**、**上游社区数据卷积**、**漏洞安全数据卷积**、**License合规数据卷积**、**统计数据预计算**等。

[流程步骤配置文件](https://github.com/opensourceways/sbom-service/blob/main/batch/src/main/resources/spring-batch/sbom-read-job.xml)。

# 导入流程1.0（已弃用）

根据导入数据的相互依赖关系，依次进行：监控数据解析、软件成分分析、依赖组件分析、SBOM元数据存储、外部数据卷积等步骤。

1. 通过Spring Batch将各步骤逻辑模块化拆解，实现：代码解耦、业务解耦；
2. 使用SkipAnalyzeSbomContentDecider，判读原始数据类型：原始态的SBOM文件、eBPF监控数据、高阶语言包管理器配置文件；从而决定对应的下一步骤；
3. 将涉及外部请求的步骤进行并发处理，提高处理效率，包括：CVE Manager数据抽取、[OSSIndex](https://ossindex.sonatype.org/)漏洞库数据抽取、[貂蝉License库](https://compliance.openeuler.org/)数据抽取、上游社区信息解析。

![import-sbom-job-1.0.png](https://raw.githubusercontent.com/opensourceways/sbom-service/main/doc/assert/import-sbom-job-1.0.png)

# 导入流程2.0（当前版本）

在1.0版本模块化拆分的基础上，对模块执行顺序和模块内部逻辑进行优化，优化导入耗时。

预计openEuler ISO制品导入，识别内容包含：1.6w+软件包、3K+子module组件、1.5K+外部依赖组件、5.6w+的补丁引用关系、7.6w+的License申明信息、5.9w+的运行时依赖、所有软件包/内外部组件的漏洞查询；耗时30-35min。

[修改PR](https://github.com/opensourceways/sbom-service/pull/167)

1. 将“resolveMavenDepTask”，“supplySourceInfo”，“extractLicense”的数据抽取方式，由“外部请求”改为“外部请求+增量缓存”，减少大量的外部请求IO耗时；
2. 根据各步骤处理的数据场景进行分组拆分：package->PURL和package->repo，两组并行互不影响，不做无用的等待。

![import-sbom-job-2.0.png](https://raw.githubusercontent.com/opensourceways/sbom-service/main/doc/assert/import-sbom-job-2.0.png)

# 导入流程3.0（开发中）

在2.0版本执行顺序调整和模块逻辑优化基础上，进一步优化数据来源和扩充外部依赖组件识别能力。

预计openEuler ISO制品导入，识别内容包含：1.6w+软件包、3K+子module组件、1.5K+外部依赖组件、5.6w+的补丁引用关系、7.6w+的License申明信息、5.9w+的运行时依赖、所有软件包/内外部组件的漏洞查询；耗时10-15min。

1. 自建统一漏洞库，异步对接业界主流漏洞源并聚合统一存储；SBOM Service直接对接统一漏洞库以替代“extractOssIndex”和“extractCveManger”；提高外部漏洞数据抽取的数据精度和效率；
2. 已具备基于Maven包管理器的外部依赖组件识别能力，再新增Pypi、NPM等包管理器的支持。

![import-sbom-job-3.0.png](https://raw.githubusercontent.com/opensourceways/sbom-service/main/doc/assert/import-sbom-job-3.0.png)

---

[返回目录](../../README.md)
