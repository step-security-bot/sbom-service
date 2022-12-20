package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.model.pojo.vo.repo.OpenEulerAdvisorVo;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public class YamlUtil<T> {

    public static OpenEulerAdvisorVo parseFromStr(String yamlContent) {
        if (!StringUtils.hasText(yamlContent)) {
            return null;
        }

        TypeDescription personDesc = new TypeDescription(OpenEulerAdvisorVo.class);
        personDesc.substituteProperty("git_url", String.class, "getGitUrl", "setGitUrl");
        personDesc.substituteProperty("version_control", String.class, "getVersionControl", "setVersionControl");
        personDesc.substituteProperty("src_repo", String.class, "getSrcRepo", "setSrcRepo");
        personDesc.substituteProperty("tag_prefix", String.class, "getTagPrefix", "setTagPrefix");

        Constructor constructor = new Constructor(OpenEulerAdvisorVo.class);
        constructor.addTypeDescription(personDesc);

        Representer representer = new Representer();
        representer.addTypeDescription(personDesc);
        representer.getPropertyUtils().setSkipMissingProperties(true);

        Yaml yaml = new Yaml(constructor, representer);
        return yaml.load(yamlContent);
    }

    public static Map<String, String> LoadYamlFromInputStream(InputStream io) throws IOException {

        return new Yaml().load(io);
    }

}
