<!--
project: "SBOM Service"
title: 查询制品license详情
date: 2022-10-27  
maintainer: "ZXF"
comment: "" 
-->

# 查询制品license

## API接口

GET /sbom-api/queryLicenseUniversalApi

### 查询参数

`productName`: 查询的制品名 string      *必需*

`license`: 查询license的Id string        *非必需*

`isLegal`: license是否合规 boolean        *非必需*

`page`: 分页页数 默认0 int        *非必需*

`size`: 单页数量 默认15 int      *非必需*

### HTTP状态码

```text
200: OK
500: Internal Server Error
```

### 返回字段说明

```text
content: 分页内容 list
  licenseId: spdx license ID String
  licenseName: license名字 String
  licenseUrl: license官网地址 String
  legal: license合规性 Boolean
  count: 制品中此license的数量 BigInteger
  
last: 当前页是否最后一页 boolean
totalElements: 总元素数量 long
totalPages: 总页数 int
size: 单页最大元素数量 int
number: 当前页数  int
first: 当前页是否第一页 boolean
numberOfElements: 当前页元素数量 int
empty: 当前页是否为空  boolean
```

### 样例

#### 请求-1

GET /sbom-api/queryLicenseUniversalApi?productName=openEuler-22.03-LTS-everything-x86_64-dvd.iso

#### 返回-1

```json
{
  "content": [
    {
      "licenseId": "0BSD",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "advertising",
      "licenseName": null,
      "licenseUrl": null,
      "count": 2,
      "legal": false
    },
    {
      "licenseId": "AFL",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "AFLv3.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "AGPL-3.0-only",
      "licenseName": null,
      "licenseUrl": null,
      "count": 4,
      "legal": true
    },
    {
      "licenseId": "AGPLv3",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "ANTLR-PD",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "Apache-1.1",
      "licenseName": "Apache Software License, Version 1.1",
      "licenseUrl": "https://opensource.org/licenses/Apache-1.1",
      "count": 5,
      "legal": true
    },
    {
      "licenseId": "Apache-2.0",
      "licenseName": "Apache License, Version 2.0",
      "licenseUrl": "https://www.apache.org/licenses/LICENSE-2.0",
      "count": 353,
      "legal": true
    },
    {
      "licenseId": "Apache License 2.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "APAFML",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": false
    },
    {
      "licenseId": "APSL-1.1",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "APSL 2.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "Artistic",
      "licenseName": null,
      "licenseUrl": null,
      "count": 71,
      "legal": false
    },
    {
      "licenseId": "Artistic-1.0",
      "licenseName": "Artistic License, Version 1.0",
      "licenseUrl": "https://opensource.org/licenses/Artistic-1.0",
      "count": 108,
      "legal": false
    }
  ],
  "totalElements": 141,
  "totalPages": 10,
  "last": false,
  "size": 15,
  "number": 0,
  "numberOfElements": 15,
  "first": true,
  "empty": false
}
```

#### 请求-2

GET /sbom-api/queryLicenseUniversalApi?productName=openEuler-22.03-LTS-everything-x86_64-dvd.iso&license=Apache-2.0

#### 返回-2

```json
{
  "content": [
    {
      "licenseId": "Apache-2.0",
      "licenseName": "Apache License, Version 2.0",
      "licenseUrl": "https://www.apache.org/licenses/LICENSE-2.0",
      "count": 353,
      "legal": true
    }
  ],
  "totalElements": 1,
  "totalPages": 1,
  "last": true,
  "size": 15,
  "number": 0,
  "numberOfElements": 1,
  "first": true,
  "empty": false
}
```

#### 请求-3

GET /sbom-api/queryLicenseUniversalApi?productName=openEuler-22.03-LTS-everything-x86_64-dvd.iso&isLegal=true

#### 返回-3

```json
{
  "content": [
    {
      "licenseId": "0BSD",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "AFL",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "AFLv3.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "AGPL-3.0-only",
      "licenseName": null,
      "licenseUrl": null,
      "count": 4,
      "legal": true
    },
    {
      "licenseId": "AGPLv3",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "ANTLR-PD",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "Apache-1.1",
      "licenseName": "Apache Software License, Version 1.1",
      "licenseUrl": "https://opensource.org/licenses/Apache-1.1",
      "count": 5,
      "legal": true
    },
    {
      "licenseId": "Apache-2.0",
      "licenseName": "Apache License, Version 2.0",
      "licenseUrl": "https://www.apache.org/licenses/LICENSE-2.0",
      "count": 353,
      "legal": true
    },
    {
      "licenseId": "Apache License 2.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "APSL-1.1",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "APSL 2.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "Artistic-1.0-cl8",
      "licenseName": null,
      "licenseUrl": null,
      "count": 1,
      "legal": true
    },
    {
      "licenseId": "Artistic-1.0-Perl",
      "licenseName": null,
      "licenseUrl": null,
      "count": 9,
      "legal": true
    },
    {
      "licenseId": "Artistic-2.0",
      "licenseName": "Artistic License, Version 2.0",
      "licenseUrl": "https://opensource.org/licenses/Artistic-2.0",
      "count": 10,
      "legal": true
    },
    {
      "licenseId": "Artistic 2.0",
      "licenseName": null,
      "licenseUrl": null,
      "count": 3,
      "legal": true
    }
  ],
  "totalElements": 96,
  "totalPages": 7,
  "last": false,
  "size": 15,
  "number": 0,
  "numberOfElements": 15,
  "first": true,
  "empty": false
}
```