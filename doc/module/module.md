# sbom-tools

sbom-tools通过对业界开源服务和SBOM生态工具进行改造，实现构建过程监控、构建元数据解析、SBOM格式数据转换等功能。包含：ORT、eBPF、Syft等

## [sbom-generator](https://github.com/opensourceways/sbom-tools/tree/main/sbom-generator "sbom-generator")

基于Syft进行改造，新增对RPM包管理数据库repodata的解析。完成对openEuler镜像文件或者文件夹的逆向解析，生成SBOM中间态数据文件。

## [sbom-ort](https://github.com/opensourceways/sbom-tools/tree/main/sbom-ort "sbom-ort")

ORT是一款开源软件依赖审查工具套件，对其进行改造用于对构建元数据解析、SBOM数据格式转换等。

## [sbom-tracer](https://github.com/opensourceways/sbom-tools/tree/main/sbom-tracer "sbom-tracer")

BCC是一个继承BPF的开源Linux动态跟踪工具，可对程序进行高效而安全的跟踪。基于BCC中的[sslsniff](https://github.com/iovisor/bcc/blob/master/tools/sslsniff.pyhttps:/)、[execsnoop](https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py)进行改造，实现监控构建过程中对依赖软件的操作，包括：进程命令、网络请求等。

# Acknowledgement

[Syft](https://github.com/anchore/syft)

[ORT](https://github.com/oss-review-toolkit/ort)

[BCC](https://github.com/iovisor/bcc)
