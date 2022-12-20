package org.opensourceway.sbom.utils;

import org.apache.commons.lang3.StringUtils;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;


public class JsonContainsMatcher<T> extends BaseMatcher<T> {

    private final String matchContent;

    public JsonContainsMatcher(String value) {
        this.matchContent = value;
    }

    @Override
    public boolean matches(Object input) {
        return StringUtils.contains(String.valueOf(input), matchContent);
    }

    public void describeTo(Description description) {
        description.appendText("value not contains" + matchContent);
    }

}