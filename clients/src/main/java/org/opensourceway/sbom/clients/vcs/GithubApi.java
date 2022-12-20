package org.opensourceway.sbom.clients.vcs;

import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.pojo.response.vcs.github.GithubRepoInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

@Component
public class GithubApi implements VcsApi {

    @Value("${github.api.url}")
    private String defaultBaseUrl;

    @Value("${github.api.token}")
    private String token;

    private WebClient createWebClient() {
        return WebClient.create(this.defaultBaseUrl);
    }

    @Override
    public Mono<GithubRepoInfo.RepoInfo> getRepoInfo(String org, String repo) {
        return createWebClient().get()
                .uri("/repos/%s/%s".formatted(org, repo))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GithubRepoInfo.RepoInfo.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));

    }
}
