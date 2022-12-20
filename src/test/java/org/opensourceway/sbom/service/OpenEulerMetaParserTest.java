package org.opensourceway.sbom.service;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.api.repo.RepoMetaParser;
import org.opensourceway.sbom.model.pojo.vo.repo.MetaServiceDomain;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;
import org.opensourceway.sbom.utils.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class OpenEulerMetaParserTest {

    @Autowired
    private RepoMetaParser repoMetaParser;

    @Test
    public void fetchObsMetaSourceCodeTest() throws IOException {
        List<RepoInfoVo> repoInfoList = repoMetaParser.fetchObsMetaSourceCode().stream().toList();
        assertThat(repoInfoList.size()).isGreaterThan(4900);
        assertThat(repoInfoList.get(0).getRepoName()).isEqualTo("A-Tune");
        assertThat(repoInfoList.get(0).getBranch()).isEqualTo("openEuler-20.03-LTS-SP2");
    }

    @Test
    public void repoInfoDistinctTest() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();
        repoInfoSet.add(new RepoInfoVo("three-eight-nine-ds-base", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("CUnit", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("CUnit", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("texlive-split-m", "openEuler-22.03-LTS"));

        assertThat(repoInfoSet.size()).isEqualTo(3);

        RepoInfoVo[] repoInfoArr = repoInfoSet.toArray(new RepoInfoVo[0]);
        assertThat(repoInfoArr[0].getRepoName()).isEqualTo("three-eight-nine-ds-base");
        assertThat(repoInfoArr[1].getRepoName()).isEqualTo("CUnit");
        assertThat(repoInfoArr[2].getRepoName()).isEqualTo("texlive-split-m");
    }

    @Test
    public void multiRepoInfoTest() throws IOException {
        ClassPathResource serviceResource = new ClassPathResource(TestConstants.SAMPLE_OBS_META_SERVICE_FILE_NAME);
        String fileContent = IOUtils.toString(serviceResource.getInputStream(), Charset.defaultCharset());

        MetaServiceDomain metaService = Mapper.xmlMapper.readValue(fileContent, MetaServiceDomain.class);
        Set<RepoInfoVo> repoInfoSet = metaService.getRepoInfo();
        assertThat(repoInfoSet.size()).isEqualTo(3);

        List<RepoInfoVo> repoInfoList = repoInfoSet.stream().toList();
        assertThat(repoInfoList.get(0).getRepoName()).isEqualTo("openEuler-kernel");
        assertThat(repoInfoList.get(1).getRepoName()).isEqualTo("kata_integration");
        assertThat(repoInfoList.get(2).getRepoName()).isEqualTo("kata-containers");
    }

    @Test
    public void fetchRepoInfoTest() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();
        repoInfoSet.add(new RepoInfoVo("three-eight-nine-ds-base", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("CUnit", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("texlive-split-m", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("kata_integration", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("kata-containers", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("openEuler-repos", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("apache-commons-beanutils", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("openEuler-kernel", "openEuler-22.03-LTS"));

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoBuildFileInfo(repoInfo);
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        List<RepoInfoVo> repoInfoList = repoInfoSet.stream().toList();
        assertThat(repoInfoList.get(0).getDownloadLocation()).isEqualTo("https://gitee.com/src-openeuler/three-eight-nine-ds-base/tree/openEuler-22.03-LTS");
        assertThat(repoInfoList.get(0).getSpecDownloadUrl()).isEqualTo("https://gitee.com/src-openeuler/three-eight-nine-ds-base/raw/openEuler-22.03-LTS/389-ds-base.spec");
        assertThat(repoInfoList.get(0).getUpstreamDownloadUrls().size()).isEqualTo(2);
        assertThat(repoInfoList.get(0).getUpstreamDownloadUrls().contains("https://gitee.com/src-openeuler/three-eight-nine-ds-base/raw/openEuler-22.03-LTS/jemalloc.yaml")).isTrue();
        assertThat(repoInfoList.get(0).getPatchInfo().get(0)).isEqualTo("CVE-2021-3652.patch");
        assertThat(repoInfoList.get(0).getPatchInfo().get(2)).isEqualTo("Fix-attributeError-type-object-build_manpages.patch");
        assertThat(repoInfoList.get(0).getPackageNames().get(0)).isEqualTo("389-ds-base");
        assertThat(repoInfoList.get(0).getPackageNames().get(3)).isEqualTo("389-ds-base-snmp");
        assertThat(repoInfoList.get(0).getPackageNames().get(4)).isEqualTo("python3-lib389");

        assertThat(repoInfoList.get(1).getDownloadLocation()).isEqualTo("https://gitee.com/src-openeuler/CUnit/tree/openEuler-22.03-LTS");
        assertThat(repoInfoList.get(1).getSpecDownloadUrl()).isEqualTo("https://gitee.com/src-openeuler/CUnit/raw/openEuler-22.03-LTS/CUnit.spec");
        assertThat(repoInfoList.get(1).getUpstreamDownloadUrls().size()).isEqualTo(1);
        assertThat(repoInfoList.get(1).getPatchInfo()).isNull();
        assertThat(repoInfoList.get(1).getPackageNames().size()).isEqualTo(3);

        assertThat(repoInfoList.get(2).getDownloadLocation()).isEqualTo("https://gitee.com/src-openeuler/texlive-split-m/tree/openEuler-22.03-LTS");
        assertThat(repoInfoList.get(2).getUpstreamDownloadUrls().size()).isEqualTo(1);
        assertThat(repoInfoList.get(2).getUpstreamDownloadUrls().contains("https://gitee.com/src-openeuler/texlive-split-m/raw/openEuler-22.03-LTS/texlive-split-m.yaml")).isTrue();
        assertThat(repoInfoList.get(2).getPackageNames().size()).isEqualTo(140);

        assertThat(repoInfoList.get(5).getPackageNames().size()).isEqualTo(2);
        assertThat(repoInfoList.get(5).getPackageNames().get(0)).isEqualTo("openEuler-repos");
        assertThat(repoInfoList.get(5).getPackageNames().get(1)).isEqualTo("openEuler-gpg-keys");

        assertThat(repoInfoList.get(6).getPackageNames().size()).isEqualTo(2);
        assertThat(repoInfoList.get(6).getPackageNames().get(0)).isEqualTo("apache-commons-beanutils");
        assertThat(repoInfoList.get(6).getPackageNames().get(1)).isEqualTo("apache-commons-beanutils-javadoc");

        assertThat(repoInfoList.get(7).getLastCommitId()).isNull();
        assertThat(repoInfoList.get(7).getDownloadLocation()).isNull();
        assertThat(repoInfoList.get(7).getSpecDownloadUrl()).isNull();
        assertThat(repoInfoList.get(7).getUpstreamDownloadUrls()).isNull();
        assertThat(repoInfoList.get(7).getPatchInfo()).isNull();
        assertThat(repoInfoList.get(7).getPackageNames()).isNull();
    }

    /**
     * java.lang.NullPointerException: Cannot invoke "String.length()" because "this.input" is null caused by spec not exists
     */
    @Test
    public void specNotExistTest() {
        RepoInfoVo repoInfo1 = new RepoInfoVo("jakarta-server-pages", "openEuler-22.03-LTS");
        RepoInfoVo repoInfo2 = new RepoInfoVo("python-croniter", "openEuler-22.03-LTS");

        repoMetaParser.fetchRepoBuildFileInfo(repoInfo1);
        repoMetaParser.fetchRepoBuildFileInfo(repoInfo2);

        assertThat(repoInfo1.getLastCommitId()).isNull();
        assertThat(repoInfo1.getDownloadLocation()).isNull();
        assertThat(repoInfo1.getSpecDownloadUrl()).isNull();
        assertThat(repoInfo1.getUpstreamDownloadUrls()).isNull();
        assertThat(repoInfo1.getPatchInfo()).isNull();
        assertThat(repoInfo1.getPackageNames()).isNull();

        assertThat(repoInfo2.getLastCommitId()).isNull();
        assertThat(repoInfo2.getDownloadLocation()).isNull();
        assertThat(repoInfo2.getSpecDownloadUrl()).isNull();
        assertThat(repoInfo2.getUpstreamDownloadUrls()).isNull();
        assertThat(repoInfo2.getPatchInfo()).isNull();
        assertThat(repoInfo2.getPackageNames()).isNull();
    }

    @Test
    public void specMacroDuplicateTest() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("alsa-firmware", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/alsa-firmware/raw/openEuler-22.03-LTS/alsa-firmware.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("emacs", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/emacs/raw/openEuler-22.03-LTS/emacs.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("glibc", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/glibc/raw/openEuler-22.03-LTS/glibc.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("google-noto-fonts", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/google-noto-fonts/raw/openEuler-22.03-LTS/google-noto-fonts.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("grub2", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/grub2/raw/openEuler-22.03-LTS/grub2.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("kde-filesystem", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/kde-filesystem/raw/openEuler-22.03-LTS/kde-filesystem.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("libkcapi", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/libkcapi/raw/openEuler-22.03-LTS/libkcapi.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("jemalloc", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/jemalloc/raw/openEuler-22.03-LTS/jemalloc.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("libvirt", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/libvirt/raw/openEuler-22.03-LTS/libvirt.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("mesa", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/mesa/raw/openEuler-22.03-LTS/mesa.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("openblas", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/openblas/raw/openEuler-22.03-LTS/openblas.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("openEuler-release", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/openEuler-release/raw/openEuler-22.03-LTS/generic-release.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("p11-kit", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/p11-kit/raw/openEuler-22.03-LTS/p11-kit.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("pacemaker", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/pacemaker/raw/openEuler-22.03-LTS/pacemaker.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("parted", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/parted/raw/openEuler-22.03-LTS/parted.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("rust", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/rust/raw/openEuler-22.03-LTS/rust.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("qt", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/qt/raw/openEuler-22.03-LTS/qt.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("strace", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/strace/raw/openEuler-22.03-LTS/strace.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("udisks2", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/udisks2/raw/openEuler-22.03-LTS/udisks2.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("urw-base35-fonts", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/urw-base35-fonts/raw/openEuler-22.03-LTS/urw-base35-fonts.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("deepin-desktop-schemas", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/deepin-desktop-schemas/raw/openEuler-22.03-LTS/deepin-desktop-schemas.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("etckeeper", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/etckeeper/raw/openEuler-22.03-LTS/etckeeper.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("openconnect", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/openconnect/raw/openEuler-22.03-LTS/openconnect.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("ovirt-provider-ovn", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/ovirt-provider-ovn/raw/openEuler-22.03-LTS/ovirt-provider-ovn.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("vdsm", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/vdsm/raw/openEuler-22.03-LTS/vdsm.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("valgrind", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/valgrind/raw/openEuler-22.03-LTS/valgrind.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }
        boolean isSuccess = true;
        for (RepoInfoVo repoInfoVo : repoInfoSet) {
            if (CollectionUtils.isEmpty((repoInfoVo.getPackageNames()))) {
                isSuccess = false;
            }
        }
        assertThat(isSuccess).isTrue();
    }


    /**
     * java.lang.NullPointerException: Cannot invoke "String.length()" because "replacement" is null
     */
    @Test
    public void specMacroError1Test() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("mingw-filesystem", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/mingw-filesystem/raw/openEuler-22.03-LTS/mingw-filesystem.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("openEuler-indexhtml", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/openEuler-indexhtml/raw/openEuler-22.03-LTS/generic-indexhtml.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("openEuler-repos", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/openEuler-repos/raw/openEuler-22.03-LTS/generic-repos.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("openEuler-rpm-config", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/openEuler-rpm-config/raw/openEuler-22.03-LTS/openEuler-rpm-config.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("kernel", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/kernel/raw/openEuler-22.03-LTS/kernel-rt.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("spdk", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/spdk/raw/openEuler-22.03-LTS/spdk.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("tbb", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/tbb/raw/openEuler-22.03-LTS/tbb.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        List<RepoInfoVo> repoInfoList = repoInfoSet.stream().toList();
        assertThat(repoInfoList.get(0).getPackageNames().size()).isEqualTo(4);
        assertThat(repoInfoList.get(0).getPackageNames().get(0)).isEqualTo("mingw-filesystem");
        assertThat(repoInfoList.get(0).getPackageNames().get(2)).isEqualTo("mingw32-filesystem");
        assertThat(repoInfoList.get(0).getPackageNames().get(3)).isEqualTo("mingw64-filesystem");

        assertThat(repoInfoList.get(4).getPackageNames().contains("kernel-rt")).isTrue();
        assertThat(repoInfoList.get(4).getPackageNames().contains("kernel-rt-devel")).isTrue();
        assertThat(repoInfoList.get(4).getPackageNames().contains("kernel-rt-headers")).isTrue();
        assertThat(repoInfoList.get(4).getPackageNames().contains("kernel-rt-source")).isTrue();
        assertThat(repoInfoList.get(4).getPackageNames().contains("kernel-rt-tools")).isTrue();
        assertThat(repoInfoList.get(4).getPackageNames().contains("kernel-rt-tools-devel")).isTrue();
    }


    /**
     * java.lang.IndexOutOfBoundsException: No group 1. for example:
     * <p>
     * %define version_no_minor %(echo %{version} | awk -F. '{print $1"."$2}')
     */
    @Test
    public void specMacroError2Test() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("atkmm", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/atkmm/raw/openEuler-22.03-LTS/atkmm.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("python-psycopg2", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/python-psycopg2/raw/openEuler-22.03-LTS/python-psycopg2.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("vim", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/vim/raw/openEuler-22.03-LTS/vim.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        assertThat(repoInfoSet.size()).isEqualTo(3);
    }

    /**
     * java.lang.IllegalArgumentException: Illegal group reference
     */
    @Test
    public void specMacroError3Test() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("perl-Tk", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/perl-Tk/raw/openEuler-22.03-LTS/perl-Tk.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("perl-Carp-Clan", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/perl-Carp-Clan/raw/openEuler-22.03-LTS/perl-Carp-Clan.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("freeradius", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/freeradius/raw/openEuler-22.03-LTS/freeradius.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("python-pycurl", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/python-pycurl/raw/openEuler-22.03-LTS/python-pycurl.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }
        assertThat(repoInfoSet.size()).isEqualTo(4);
        boolean isSuccess = true;
        for (RepoInfoVo repoInfoVo : repoInfoSet) {
            if (CollectionUtils.isEmpty((repoInfoVo.getPackageNames()))) {
                isSuccess = false;
            }
        }
        assertThat(isSuccess).isTrue();
    }

    /**
     * java.lang.IllegalArgumentException: character to be escaped is missing
     */
    @Test
    public void specMacroError4Test() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("google-noto-cjk-fonts", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/google-noto-cjk-fonts/raw/openEuler-22.03-LTS/google-noto-cjk-fonts.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("tesseract-tessdata", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/tesseract-tessdata/raw/openEuler-22.03-LTS/tesseract-tessdata.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        assertThat(repoInfoSet.size()).isEqualTo(2);
        boolean isSuccess = true;
        for (RepoInfoVo repoInfoVo : repoInfoSet) {
            if (CollectionUtils.isEmpty((repoInfoVo.getPackageNames()))) {
                isSuccess = false;
            }
        }
        assertThat(isSuccess).isTrue();
    }

    /**
     * java.lang.NullPointerException: null
     */
    @Test
    public void specMacroError5Test() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("rdma-core", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/rdma-core/raw/openEuler-22.03-LTS/rdma-core.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("squid", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/squid/raw/openEuler-22.03-LTS/squid.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("ovirt-cockpit-sso", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/ovirt-cockpit-sso/raw/openEuler-22.03-LTS/ovirt-cockpit-sso.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("ovirt-engine-nodejs-modules", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/ovirt-engine-nodejs-modules/raw/openEuler-22.03-LTS/ovirt-engine-nodejs-modules.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }
        assertThat(repoInfoSet.size()).isEqualTo(4);
        boolean isSuccess = true;
        for (RepoInfoVo repoInfoVo : repoInfoSet) {
            if (CollectionUtils.isEmpty((repoInfoVo.getPackageNames()))) {
                isSuccess = false;
            }
        }
        assertThat(isSuccess).isTrue();
    }


    /**
     * spec name variable is null,for example
     * <p>
     * Name :         perl-List-MoreUtils-XS
     */
    @Test
    public void specMacroNameWithSpaceTest() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("perl-List-MoreUtils-XS", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/perl-List-MoreUtils-XS/raw/openEuler-22.03-LTS/perl-List-MoreUtils-XS.spec");
        repoInfoSet.add(temp);

        temp = new RepoInfoVo("security-tool", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/security-tool/raw/openEuler-22.03-LTS/security-tool.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }
        assertThat(repoInfoSet.size()).isEqualTo(2);

        List<RepoInfoVo> repoInfoList = repoInfoSet.stream().toList();
        assertThat(repoInfoList.get(0).getPackageNames().get(0)).isEqualTo("perl-List-MoreUtils-XS");
        assertThat(repoInfoList.get(0).getPackageNames().get(1)).isEqualTo("perl-List-MoreUtils-XS-help");
        assertThat(repoInfoList.get(1).getPackageNames().get(0)).isEqualTo("security-tool");
    }

    @Test
    public void specPackageHelpMacroTest() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();

        RepoInfoVo temp = new RepoInfoVo("grilo", "openEuler-22.03-LTS");
        temp.setSpecDownloadUrl("https://gitee.com/src-openeuler/grilo/raw/openEuler-22.03-LTS/grilo.spec");
        repoInfoSet.add(temp);

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        List<RepoInfoVo> repoInfoList = repoInfoSet.stream().toList();
        assertThat(repoInfoList.get(0).getPackageNames().get(0)).isEqualTo("grilo");
        assertThat(repoInfoList.get(0).getPackageNames().get(1)).isEqualTo("grilo-devel");
        assertThat(repoInfoList.get(0).getPackageNames().get(2)).isEqualTo("grilo-help");
    }

}
