package org.opensourceway.sbom.utils;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class PurlTest {
    @Test
    public void normalPurl() {
        assertThat(PurlUtil.canonicalizePurl("pkg:rpm/ImageMagick@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath"))
                .isEqualTo("pkg:rpm/ImageMagick@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath");
    }

    @Test
    public void purlWithPlus() {
        assertThat(PurlUtil.canonicalizePurl("pkg:rpm/ImageMagick-c++-devel@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath"))
                .isEqualTo("pkg:rpm/ImageMagick-c++-devel@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath");
    }

    @Test
    public void purlWithAsterisk() {
        assertThat(PurlUtil.canonicalizePurl("pkg:rpm/ImageMagick-c**-devel@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath"))
                .isEqualTo("pkg:rpm/ImageMagick-c**-devel@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath");
    }

    @Test
    public void purlWithTilde() {
        assertThat(PurlUtil.canonicalizePurl("pkg:rpm/ImageMagick-c~~-devel@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath"))
                .isEqualTo("pkg:rpm/ImageMagick-c~~-devel@7.1.0.27-1.oe2203?arch=x86_64&epoch=1&upstream=ImageMagick-7.1.0.27-1.oe2203.src.rpm#subpath");
    }
}
