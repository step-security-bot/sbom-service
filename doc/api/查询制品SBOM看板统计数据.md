<!--
project: "SBOM Service"
title: 查询SBOM看板
date: 2022-09-24
maintainer: huanceng
comment: "此文档包含了2个接口，共同组成看板：
            1. 查询制品最新看板数据
            2. 查询制品漏洞趋势"
-->

# 1. 查询制品最新看板数据

## API接口
GET /sbom-api/queryProductStatistics/{productName}

### 路径参数
`productName`: 查询的制品名    string      *必需*

### HTTP状态码
```text
200: OK
500: Internal Server Error
```

### 返回字段说明
```text
id: 数据库主键，可忽略   string
createTime: 制品SBOM生成时间  string
packageCount: 软件数量  long
depCount: 依赖数量  long
moduleCount: 模块数量   long
runtimeDepCount: 运行时依赖数量    long
vulCount: 漏洞数量  long
licenseCount: license种类数量   long
criticalVulCount: 致命漏洞数量    long
highVulCount: 高危漏洞数量    long
mediumVulCount: 中危漏洞数量  long
lowVulCount: 低危漏洞数量 long
noneVulCount: 无风险漏洞数量   long
unknownVulCount: 未知漏洞数量 long
packageWithCriticalVulCount: 包含致命漏洞的软件数量    long
packageWithHighVulCount: 包含高危漏洞的软件数量    long
packageWithMediumVulCount: 包含中危漏洞的软件数量  long
packageWithLowVulCount: 包含低危漏洞的软件数量 long
packageWithNoneVulCount: 包含无风险漏洞的软件数量   long
packageWithUnknownVulCount: 包含未知漏洞的软件数量 long
packageWithoutVulCount: 不包含漏洞的软件数量  long
packageWithLegalLicenseCount: 包含合规license的软件数量  long
packageWithIllegalLicenseCount: 包含不合规license的软件数量   long
packageWithoutLicenseCount: 不包含license的软件数量 long
packageWithMultiLicenseCount: 包含多license的软件数量   long
licenseDistribution: license分布  map<string, long>
```

### 样例
#### 请求
GET /sbom-api/queryProductStatistics/testProductName

#### 返回
```json
{
    "id": "4ef135d8-0b67-4b9f-a41c-019d9ef2bfa6",
    "createTime": "2022-09-15T14:03:20.000+00:00",
    "packageCount": 1000,
    "depCount": 2000,
    "moduleCount": 3000,
    "runtimeDepCount": 0,
    "vulCount": 500,
    "licenseCount": 600,
    "criticalVulCount": 70,
    "highVulCount": 80,
    "mediumVulCount": 90,
    "lowVulCount": 100,
    "noneVulCount": 110,
    "unknownVulCount": 50,
    "packageWithCriticalVulCount": 130,
    "packageWithHighVulCount": 140,
    "packageWithMediumVulCount": 150,
    "packageWithLowVulCount": 160,
    "packageWithNoneVulCount": 170,
    "packageWithUnknownVulCount": 180,
    "packageWithoutVulCount": 70,
    "packageWithLegalLicenseCount": 200,
    "packageWithIllegalLicenseCount": 210,
    "packageWithoutLicenseCount": 190,
    "packageWithMultiLicenseCount": 100,
    "licenseDistribution": {
        "MIT": 20,
        "Apache-2.0": 500
    }
}
```

# 2. 查询制品漏洞趋势

## API接口
GET /sbom-api/queryProductVulTrend/{productName}

### 路径参数
`productName`: 查询的制品名    string      *必需*

### 查询参数
`startTimestamp`: 查询起始毫秒时间戳；未指定时，为(endTimestamp - 1个月)    long      *非必需*

`endTimestamp`: 查询结束毫秒时间戳；未指定时，为(当前时间戳)    long      *非必需*

### HTTP状态码
```text
200: OK
500: Internal Server Error
```

### 返回字段说明
```text
timestamp: 制品SBOM生成毫秒时间戳
criticalVulCount: 致命漏洞数量    long
highVulCount: 高危漏洞数量    long
mediumVulCount: 中危漏洞数量  long
lowVulCount: 低危漏洞数量 long
noneVulCount: 无风险漏洞数量   long
unknownVulCount: 未知漏洞数量 long
```

### 样例
#### 请求
GET /sbom-api/queryProductVulTrend/testProductName?startTimestamp=1663150600000&endTimestamp=1663250600000

#### 返回
```json
[
  {
    "timestamp": 1663150600000,
    "criticalVulCount": 7,
    "highVulCount": 8,
    "mediumVulCount": 9,
    "lowVulCount": 10,
    "noneVulCount": 11,
    "unknownVulCount": 5
  },
  {
    "timestamp": 1663250600000,
    "criticalVulCount": 70,
    "highVulCount": 80,
    "mediumVulCount": 90,
    "lowVulCount": 100,
    "noneVulCount": 110,
    "unknownVulCount": 50
  }
]
```

---

[返回目录](../../README.md)
