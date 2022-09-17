package org.opensourceway.sbom.clients.vcs.gitee;

import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.clients.vcs.gitee.model.GiteeRepoInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.time.Duration;

import static java.nio.file.StandardOpenOption.CREATE_NEW;

@Component
public class GiteeApi implements VcsApi {

    private static final Logger logger = LoggerFactory.getLogger(GiteeApi.class);

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

    public Path downloadRepoArchive(Path downloadDir, String org, String repo, String branch) {
        WebClient client = createWebClient();
        String downloadUri = "/%s/%s/repository/archive/%s.zip".formatted(org, repo, branch);

        ResponseEntity<String> result = client
                .get()
                .uri(downloadUri)
                .accept(MediaType.ALL)
                .header("Connection", "Keep-Alive")
                .header("User-Agent", "Wget/1.14 (linux-gnu)")// mock wget command's header, or server redirects to login uri
                .retrieve()
                .toEntity(String.class)
                .block();

        if (result == null) {
            throw new RuntimeException("gitee repo archive first download is failed");
        } else if (result.getStatusCodeValue() != 302) {
            logger.error("response status code: {}, content: {}", result.getStatusCode(), result.getBody());
            throw new RuntimeException("gitee repo archive first download not 302");
        }

        // e.g. /src-openeuler/obs_meta/repository/blazearchive/master.zip?Expires=1111111&Signature=xxxxx
        URI newDownloadUri = result.getHeaders().getLocation();
        if (newDownloadUri == null) {
            throw new RuntimeException("gitee repo archive download redirect(302) uri is null");
        }
        logger.info("gitee repo archive download redirect(302) uri:{}", newDownloadUri);

        Flux<DataBuffer> responseFlux = client
                .get()
                .uri(result.getHeaders().getLocation())
                .accept(MediaType.ALL)
                .header("Connection", "Keep-Alive")
                .header("User-Agent", "Wget/1.14 (linux-gnu)")
                .retrieve()
                .bodyToFlux(DataBuffer.class);

        Path zipPath = FileSystems.getDefault().getPath(downloadDir.toString(), branch + ".zip");
        DataBufferUtils.write(responseFlux, zipPath, CREATE_NEW).block(Duration.ofSeconds(90));
        return zipPath;
    }
}
