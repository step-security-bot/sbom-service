package org.opensourceway.sbom.model.pojo.vo.repo;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.springframework.util.CollectionUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@JacksonXmlRootElement(localName = "services")
public class MetaServiceDomain {

    @JacksonXmlProperty(localName = "service")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<ServiceDomain> services;

    public List<ServiceDomain> getServices() {
        return services;
    }

    public void setServices(List<ServiceDomain> services) {
        this.services = services;
    }

    public Set<RepoInfoVo> getRepoInfo() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();
        if (CollectionUtils.isEmpty(services)) {
            return repoInfoSet;
        }

        for (ServiceDomain service : services) {
            if (CollectionUtils.isEmpty(service.getParams())) {
                continue;
            }

            for (ParamDomain param : service.getParams()) {
                if ("url".equals(param.getName())) {
                    String[] valueArr = param.getParamValue().split(SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR);
                    if (valueArr.length > 2) {
                        String branch = valueArr[1];
                        String repo = valueArr[2];
                        repoInfoSet.add(new RepoInfoVo(repo, branch));
                    }
                }
            }
        }
        return repoInfoSet;
    }
}

class ServiceDomain {

    @JacksonXmlProperty(localName = "name", isAttribute = true)
    private String name;

    @JacksonXmlProperty(localName = "param")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<ParamDomain> params;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<ParamDomain> getParams() {
        return params;
    }

    public void setParams(List<ParamDomain> params) {
        this.params = params;
    }
}

class ParamDomain {

    @JacksonXmlProperty(localName = "name", isAttribute = true)
    private String name;

    @JacksonXmlText
    private String paramValue;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getParamValue() {
        return paramValue;
    }

    public void setParamValue(String paramValue) {
        this.paramValue = paramValue;
    }
}