package org.opensourceway.sbom.clients.vcs.gitee;

import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.clients.vcs.gitee.model.GiteeRepoInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

@Component
public class GiteeApi implements VcsApi {
    @Value("${gitee.api.url}")
    private String defaultBaseUrl;

    @Value("${gitee.api.token}")
    private String token;

    private WebClient createWebClient() {
        return WebClient.create(this.defaultBaseUrl);
    }

    @Override
    public Mono<GiteeRepoInfo.RepoInfo> getRepoInfo(String org, String repo) {
        return createWebClient().get()
                .uri("/api/v5/repos/%s/%s".formatted(org, repo))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GiteeRepoInfo.RepoInfo.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));

    }
}
