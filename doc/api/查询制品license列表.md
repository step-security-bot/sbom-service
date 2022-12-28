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

`orderBy`: 排序规则 默认licenseId String        *非必需*

`page`: 分页页数 默认0 int        *非必需*

`size`: 单页数量 默认15 int      *非必需*

| orderBy 可选值 | 说明                  |
|-------------|---------------------|
| licenseId   | 默认值，按照licenseId升序排列 |
| count       | 按照license个数降序排列     |

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

#### 请求-4

GET
/sbom-api/queryLicenseUniversalApi?productName=openEuler-22.03-LTS-everything-x86_64-dvd.iso&orderBy=count&isLegal=true

#### 返回-4

```json
{
  "content": [
    {
      "licenseId": "MIT",
      "licenseName": "MIT License",
      "licenseUrl": "https://spdx.org/licenses/MIT.html",
      "count": 8197,
      "legal": true
    },
    {
      "licenseId": "GPL-2.0-or-later",
      "licenseName": "GNU General Public License v2.0 or later",
      "licenseUrl": "https://spdx.org/licenses/GPL-2.0-or-later.html",
      "count": 7856,
      "legal": true
    },
    {
      "licenseId": "LGPL-2.0-or-later",
      "licenseName": "GNU Library General Public License v2 or later",
      "licenseUrl": "https://spdx.org/licenses/LGPL-2.0-or-later.html",
      "count": 7043,
      "legal": true
    },
    {
      "licenseId": "GPL-2.0-only",
      "licenseName": "GNU General Public License v2.0 only",
      "licenseUrl": "https://spdx.org/licenses/GPL-2.0-only.html",
      "count": 6908,
      "legal": true
    },
    {
      "licenseId": "LicenseRef-scancode-public-domain-disclaimer",
      "licenseName": null,
      "licenseUrl": null,
      "count": 6150,
      "legal": true
    },
    {
      "licenseId": "UCD",
      "licenseName": null,
      "licenseUrl": null,
      "count": 5784,
      "legal": true
    },
    {
      "licenseId": "Artistic-2.0",
      "licenseName": "Artistic License 2.0",
      "licenseUrl": "https://spdx.org/licenses/Artistic-2.0.html",
      "count": 5776,
      "legal": true
    },
    {
      "licenseId": "Apache-2.0",
      "licenseName": "Apache License 2.0",
      "licenseUrl": "https://spdx.org/licenses/Apache-2.0.html",
      "count": 2191,
      "legal": true
    },
    {
      "licenseId": "BSD-3-Clause",
      "licenseName": "BSD 3-Clause \"New\" or \"Revised\" License",
      "licenseUrl": "https://spdx.org/licenses/BSD-3-Clause.html",
      "count": 1692,
      "legal": true
    },
    {
      "licenseId": "LGPL-2.1-only",
      "licenseName": "GNU Lesser General Public License v2.1 only",
      "licenseUrl": "https://spdx.org/licenses/LGPL-2.1-only.html",
      "count": 680,
      "legal": true
    },
    {
      "licenseId": "GPL-3.0-or-later",
      "licenseName": "GNU General Public License v3.0 or later",
      "licenseUrl": "https://spdx.org/licenses/GPL-3.0-or-later.html",
      "count": 474,
      "legal": true
    },
    {
      "licenseId": "GPL-3.0-only",
      "licenseName": "GNU General Public License v3.0 only",
      "licenseUrl": "https://spdx.org/licenses/GPL-3.0-only.html",
      "count": 473,
      "legal": true
    },
    {
      "licenseId": "exceptions",
      "licenseName": null,
      "licenseUrl": null,
      "count": 320,
      "legal": true
    },
    {
      "licenseId": "LGPL-3.0-only",
      "licenseName": "GNU Lesser General Public License v3.0 only",
      "licenseUrl": "https://spdx.org/licenses/LGPL-3.0-only.html",
      "count": 297,
      "legal": true
    },
    {
      "licenseId": "BSL-1.0",
      "licenseName": "Boost Software License 1.0",
      "licenseUrl": "https://spdx.org/licenses/BSL-1.0.html",
      "count": 294,
      "legal": true
    }
  ],
  "totalElements": 126,
  "totalPages": 9,
  "last": false,
  "size": 15,
  "number": 0,
  "first": true,
  "numberOfElements": 15,
  "empty": false
}
```

---

[返回目录](../../README.md)
