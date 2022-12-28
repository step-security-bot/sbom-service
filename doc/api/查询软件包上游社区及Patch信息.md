<!--
project: "SBOM Service"
title: 上游社区及Patch信息查询
date: 2022-11-10
maintainer: zejun19
comment: ""
-->

# 上游社区及Patch信息查询

## API接口

GET /sbom-api/queryUpstreamAndPatchInfo/{packageId}

### 路径参数

`packageId`: 查询的包UUID    string      *必需*

### HTTP状态码

```text
200: OK
500: Internal Server Error
```

### 返回字段说明

```text
upstreamList: 上游社区信息列表      list
  url: 上游社区原始地址         string（URL格式）
patchList: patch信息列表            list
  url: patch文件原始地址        string（URL格式）
```

### 样例

#### 请求-1

GET /sbom-api/queryUpstreamAndPatchInfo/316ff894-e58f-4f19-ad14-de5a7fb9f7dd

#### 返回-1

```json
{
  "upstreamList": [
    {
      "url": "https://gitee.com/openEuler/A-Tune"
    }
  ],
  "patchList": [
    {
      "url": "https://gitee.com/src-openeuler/A-Tune/blob/openEuler-22.03-LTS/check-whether-the-certificate-file-exists.patch"
    },
    {
      "url": "https://gitee.com/src-openeuler/A-Tune/blob/openEuler-22.03-LTS/add-FAQ-and-self-signature-certificate-manufacturing.patch"
    },
    {
      "url": "https://gitee.com/src-openeuler/A-Tune/blob/openEuler-22.03-LTS/fix-start-failed-of-atuned-service.patch"
    },
    {
      "url": "https://gitee.com/src-openeuler/A-Tune/blob/openEuler-22.03-LTS/change-Makefile-A-Tune-version-to-1.0.0.patch"
    }
  ]
}
```

#### 请求-2

GET /sbom-api/queryUpstreamAndPatchInfo/316ff894-e58f-4f19-ad14-de5a7fb9f711

#### 返回-2

```json
{
    "upstreamList": [],
    "patchList": []
}
```

---

[返回目录](../../README.md)
