package org.opensourceway.sbom.utils;

import org.junit.jupiter.api.Test;
import org.springframework.batch.core.repository.dao.Jackson2ExecutionContextStringSerializer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

/**
 * reference to https://github.com/spring-projects/spring-batch/pull/3787/files
 */
public class Jackson2ExecutionContextStringSerializerTests {

    /**
     * 测试自定义信任类
     *
     * @throws IOException
     */
    @Test
    public void testAdditionalTrustedClass() throws IOException {
        // given
        Jackson2ExecutionContextStringSerializer serializer =
                new Jackson2ExecutionContextStringSerializer("java.util.Locale");
        Map<String, Object> context = new HashMap<>(1);
        context.put("locale", Locale.getDefault());

        // when
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        serializer.serialize(context, outputStream);
        InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
        Map<String, Object> deserializedContext = serializer.deserialize(inputStream);

        // then
        Locale locale = (Locale) deserializedContext.get("locale");
        assertThat(locale).isNotNull();
    }


    /**
     * 测试多个自定义信任类
     *
     * @throws IOException
     */
    @Test
    public void testByteArrayTrustedClass() throws IOException {
        String content = "StingBytesTest";

        // given
        Jackson2ExecutionContextStringSerializer serializer =
                new Jackson2ExecutionContextStringSerializer("[B", "java.util.Locale");
        Map<String, Object> context = new HashMap<>(1);
        context.put("bytes", content.getBytes(StandardCharsets.UTF_8));

        // when
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        serializer.serialize(context, outputStream);
        InputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
        Map<String, Object> deserializedContext = serializer.deserialize(inputStream);

        // then
        byte[] bytes = (byte[]) deserializedContext.get("bytes");
        assertThat(content.equals(new String(bytes))).isTrue();
    }

}
