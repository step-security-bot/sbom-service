package org.opensourceway.sbom.clients.vcs;

import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.pojo.response.vcs.gitlab.GitlabRepoInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Component
public class GitlabApi implements VcsApi {
    @Value("${gitlab.api.url}")
    private String defaultBaseUrl;

    @Value("${gitlab.api.token}")
    private String token;

    private WebClient createWebClient() {
        return WebClient.create(this.defaultBaseUrl);
    }

    @Override
    public Mono<GitlabRepoInfo.RepoInfo> getRepoInfo(String org, String repo) {
        return createWebClient().get()
                .uri(URI.create("%s/api/v4/projects/%s%s%s?license=true".formatted(defaultBaseUrl,
                        org,
                        URLEncoder.encode(SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR, StandardCharsets.UTF_8),
                        repo)))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "Bearer %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GitlabRepoInfo.RepoInfo.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }

}
