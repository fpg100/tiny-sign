package p;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import com.android.signapk.SignApk;

public class SignTest {

    @Test
    public void test() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(SignTest.class
                .getResourceAsStream("/ApkSign.cer"));
        KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = rSAKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(IOUtils
                .toByteArray(SignTest.class.getResourceAsStream("/ApkSign.private"))));

        SignApk.sign(cert, privateKey, false, new File("src/test/resources/b.apk"), new File("target/bs.apk"));

    }
}
