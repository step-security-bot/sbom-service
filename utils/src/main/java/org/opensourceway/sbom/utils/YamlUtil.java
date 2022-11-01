package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.pojo.UpstreamInfoVo;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.representer.Representer;

public class YamlUtil<T> {

    public static UpstreamInfoVo parseFromStr(String yamlContent) {
        TypeDescription personDesc = new TypeDescription(UpstreamInfoVo.class);
        personDesc.substituteProperty("git_url", String.class, "getGitUrl", "setGitUrl");
        personDesc.substituteProperty("version_control", String.class, "getVersionControl", "setVersionControl");
        personDesc.substituteProperty("src_repo", String.class, "getSrcRepo", "setSrcRepo");
        personDesc.substituteProperty("tag_prefix", String.class, "getTagPrefix", "setTagPrefix");

        Constructor constructor = new Constructor(UpstreamInfoVo.class);
        constructor.addTypeDescription(personDesc);

        Representer representer = new Representer();
        representer.addTypeDescription(personDesc);
        representer.getPropertyUtils().setSkipMissingProperties(true);

        Yaml yaml = new Yaml(constructor, representer);
        return yaml.load(yamlContent);
    }

}
