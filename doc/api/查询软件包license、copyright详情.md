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

copyrightContent: copyright内容（暂时写死） list
  organization： 组织信息 String
  startYear： 年份 String
  additionalInfo： 其他信息 String
```

### 样例

#### 请求

GET /sbom-api/queryPackageLicenseAndCopyright/cad29380-c78b-414e-8afc-7d3bcd73dbe7

#### 返回

```json
{
  "licenseContent": [
    {
      "licenseId": "HPND",
      "licenseName": "Historical Permission Notice and Disclaimer",
      "licenseUrl": "https://opensource.org/licenses/HPND",
      "legal": true
    },
    {
      "licenseId": "MIT-open-group",
      "licenseName": null,
      "licenseUrl": null,
      "legal": false
    }
  ],
  "copyrightContent": [
    {
      "organization": "copyrightTmp",
      "startYear": "2000",
      "additionalInfo": "XXXXXXX"
    }
  ]
}
```
