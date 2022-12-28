# SBOM Service

以服务化方式提供SBOM工具链解决方案。提供一站式服务：软件成分解析、协同数据卷积、安全合规分析、SBOM导入导出、漏洞排查、直接/传递性依赖查询等；并解耦于任一SBOM协议格式。

# 开源社区SBOM解决方案应用架构全景图二级方案

依据SBOM工具链的完整规划和设计，社区SBOM应用架构可分为如下三层：

* 作业层：围绕社区开发者作业流，自动生成发布制品的SBOM、自动提交基于SBOM识别的安全合规类issue
* 服务层：根据SBOM元数据生命周期和应用场景进行服务化拆分，如[SBOM导入](https://github.com/opensourceways/sbom-service/tree/main/batch)、License合规分析、漏洞排查、漏洞感知、开源片段引用扫描、[SBOM看板服务](https://github.com/opensourceways/sbom-website)等
* 数据层：提供SBOM元数据存储、核心License数据库、漏洞数据库、开源片段数据库等数据资产

![global-architecture.png](https://raw.githubusercontent.com/opensourceways/sbom-service/main/doc/assert/global-architecture.png)

# SBOM数据组装与颗粒度

面向软件包的一包一SBOM、一包一PURL

![](https://www.openeuler.org/assets/sbom-define.f846d571.png)

# PURL（Package URL）

**PURL：** 描述软件包唯一性的一种标准协议、统一的方式识别和定位软件包、用于以跨编程语言、包管理器、打包约定、工具、API 和数据库等

**PURL表达式：** scheme:type/namespace/name@version?qualifiers#subpath

**参考：**[https://github.com/package-url/purl-spec](https://github.com/package-url/purl-spec)

![](https://www.openeuler.org/assets/purl.e75f1b4d.png)

# 效果截图

## 全局统计看板（软件成分、License、漏洞）

![](https://www.openeuler.org/assets/trend-1.8b61a8b3.png)

![](https://www.openeuler.org/assets/trend-3.74ab1ee6.png)

## SBOM软件成分查询

![](https://www.openeuler.org/assets/sca-1.73a7faa4.png)

## 单软件的SBOM **元数据详情** ，覆盖SBOM基础要素与扩展字段、完备了软件的自身可追溯性包括软件名、版本、源码、供应商、上游社区、下载地址等

![](https://www.openeuler.org/assets/sca-2.c522bff9.png)

## 单软件的License与漏洞详情，漏洞基于purl定位到组件

![](https://www.openeuler.org/assets/sca-3.4ebfaafd.png)

## 单软件正向软件全链路追溯（软件包、内部自身组件、传递性依赖、运行时依赖）

![](https://www.openeuler.org/assets/sca-4.282fc5ae.png)

## 单个软件反向追溯链全局可视,为漏洞排查奠定基础

![](https://www.openeuler.org/assets/reverse-dep.f32585cc.png)

## 单个漏洞影响范围追溯、基于反向依赖链、推到漏洞的感染的全路径、为漏洞修复提供了有利帮助

![](https://www.openeuler.org/assets/trend-6.55d4a445.png)

---

[返回目录](../../README.md)
