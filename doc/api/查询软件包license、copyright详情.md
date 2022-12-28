<!--
project: "SBOM Service"
title: 查询软件包license、copyright详情
date: 2022-09-24  
maintainer: "ZXF"
comment: "" 
-->

# 查询license、copyright

## API接口

GET /sbom-api/queryPackageLicenseAndCopyright/{packageId}

### 参数路径

`packageId`: 查询的包UUID string  *必需*

### HTTP状态码

```text
200: OK
500: Internal Server Error
```

### 返回字段说明

```text
licenseContent: license内容 list
  licenseId: spdx license ID String
  licenseName: license名字 String
  licenseUrl: license官网地址 String
  legal: license合规性 Boolean

copyrightContent: copyright内容 list
  organization： 组织信息 String
  startYear： 年份 String
  additionalInfo： 其他信息 String
```

### 样例

#### 请求

GET /sbom-api/queryPackageLicenseAndCopyright/7753b160-cf21-4b59-b8c5-0eb0368d9fc9

#### 返回

```json
{
  "licenseContent": [
    {
      "licenseId": "ASL 2.0",
      "licenseName": null,
      "licenseUrl": null,
      "legal": true
    },
    {
      "licenseId": "W3C",
      "licenseName": "The W3C Software Notice and License",
      "licenseUrl": "https://opensource.org/licenses/W3C",
      "legal": true
    }
  ],
  "copyrightContent": [
    {
      "organization": "World Wide Web Consortium",
      "startYear": "1994",
      "additionalInfo": "Copyright (c) 1994-2002 World Wide Web Consortium, (Massachusetts Institute of Technology, Institut National de Recherche en Informatique et en Automatique, Keio University)"
    }
  ]
}
```

---

[返回目录](../../README.md)
