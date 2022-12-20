package org.opensourceway.sbom.clients.vcs;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeBranchInfo;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeFileInfo;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeRepoInfo;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeTagInfo;
import org.opensourceway.sbom.utils.WebClientExceptionFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.unit.DataSize;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.nio.file.StandardOpenOption.CREATE_NEW;

@Component
public class GiteeApi implements VcsApi {

    private static final Logger logger = LoggerFactory.getLogger(GiteeApi.class);

    @Value("${gitee.api.url}")
    private String defaultBaseUrl;

    @Value("${gitee.api.token}")
    private String token;

    @Value("${spring.codec.max-in-memory-size}")
    private String maxInMemorySize;

    @Override
    public String getDefaultBaseUrl() {
        return defaultBaseUrl;
    }

    private WebClient createWebClient() {
        ExchangeStrategies strategies = ExchangeStrategies.builder()
                .codecs(codecs -> codecs.defaultCodecs().maxInMemorySize((int) DataSize.parse(maxInMemorySize).toBytes()))
                .build();
        return WebClient.builder()
                .baseUrl(this.defaultBaseUrl)
                .exchangeStrategies(strategies)
                .build();
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

    @Override
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

    /**
     * @param fileNameRegex file name regex or suffix
     * @return file name and file content map
     * @see: API DOC: <a href="https://gitee.com/api/v5/swagger#/getV5ReposOwnerRepoContents(Path)">获取仓库具体路径下的内容</a>
     */
    @Override
    public List<GiteeFileInfo> findRepoFiles(String org, String repo, String branch, String fileDir, String fileNameRegex) {
        GiteeFileInfo[] files = createWebClient().get()
                .uri(URI.create("%s/api/v5/repos/%s/%s/contents/%s?ref=%s".formatted(this.defaultBaseUrl,
                        org,
                        repo,
                        URLEncoder.encode(fileDir, StandardCharsets.UTF_8),
                        URLEncoder.encode(branch, StandardCharsets.UTF_8))))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GiteeFileInfo[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(5))
                        .filter(WebClientExceptionFilter::is5xxException))
                .block(Duration.ofSeconds(100));
        if (files == null) {
            return Collections.emptyList();
        }
        if (StringUtils.isEmpty(fileNameRegex)) {
            return Arrays.stream(files).collect(Collectors.toList());
        }

        Pattern regex = Pattern.compile(fileNameRegex, Pattern.CASE_INSENSITIVE);
        return Arrays.stream(files)
                .filter(file -> regex.matcher(file.name()).matches() || StringUtils.endsWith(file.name(), fileNameRegex))
                .collect(Collectors.toList());
    }

    @Override
    public String getFileContext(String downloadUrl) {
        return createWebClient().get()
                .uri(URI.create(downloadUrl))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(String.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> !(throwable instanceof WebClientResponseException.NotFound)))
                .block();
    }

    /**
     * @param org gitee organization name
     * @return repo names of the org
     * API DOC: <a href="https://gitee.com/api/v5/swagger#/getV5OrgsOrgRepos">获取一个组织的仓库</a>
     */
    @Override
    public List<String> getOrgRepoNames(String org, Integer page, Integer perPage) {
        GiteeRepoInfo.RepoInfo[] repoInfos = createWebClient().get()
                .uri(uriBuilder -> uriBuilder
                        .path("/api/v5/orgs/%s/repos".formatted(org))
                        .queryParam("page", page)
                        .queryParam("per_page", perPage)
                        .build())
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GiteeRepoInfo.RepoInfo[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block();

        return Arrays.stream(Optional.ofNullable(repoInfos).orElse(new GiteeRepoInfo.RepoInfo[]{}))
                .map(GiteeRepoInfo.RepoInfo::name)
                .toList();
    }

    /**
     * @param org  gitee organization name
     * @param repo gitee repo name
     * @return tags of the repo
     * API DOC: <a href="https://gitee.com/api/v5/swagger#/getV5ReposOwnerRepoTags">列出仓库的所有tags</a>
     */
    @Override
    public List<String> getRepoTags(String org, String repo) {
        GiteeTagInfo[] tags = createWebClient().get()
                .uri("/api/v5/repos/%s/%s/tags".formatted(org, repo))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GiteeTagInfo[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block();

        return Arrays.stream(Optional.ofNullable(tags).orElse(new GiteeTagInfo[]{}))
                .map(GiteeTagInfo::name)
                .toList();
    }

    @Override
    public List<GiteeBranchInfo.BranchInfo> getRepoBranches(String org, String repo) {
        GiteeBranchInfo.BranchInfo[] branches = createWebClient().get()
                .uri(URI.create("%s/api/v5/repos/%s/%s/branches".formatted(this.defaultBaseUrl,
                        org,
                        repo)))
                .headers(httpHeaders -> {
                    if (!ObjectUtils.isEmpty(token)) {
                        httpHeaders.add("Authorization", "token %s".formatted(token));
                    }
                })
                .retrieve()
                .bodyToMono(GiteeBranchInfo.BranchInfo[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(WebClientExceptionFilter::is5xxException))
                .block(Duration.ofSeconds(30));
        return Arrays.stream(Optional.ofNullable(branches).orElse(new GiteeBranchInfo.BranchInfo[]{})).toList();
    }
}
