package pxb.android.tinysign.test;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class Sha1 {

    @Test
    public void test() throws Exception {
        // String string = new String(Base64.encodeBase64(DigestUtils.sha(FileUtils.readFileToByteArray(new File(
        // "src/test/resources/a/MANIFEST.MF")))), "iso-8859-1");
        // System.out.println(string);
        // KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
        // PrivateKey privateKey = rSAKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(IOUtils.toByteArray(Sha1.class
        // .getResourceAsStream("/ApkSign.private"))));
        // Signature signature = Signature.getInstance("SHA1withRSA");
        // signature.initSign(privateKey);
        // byte[] b = FileUtils.readFileToByteArray(new File("src/test/resources/a/CERT.SF"));
        // signature.update(b);
        // byte[] d = signature.sign();
        // System.out.println(d.length);
        // System.out.println(new String(Hex.encodeHex(d)));
        // byte[] rsa = FileUtils.readFileToByteArray(new File("src/test/resources/a/CERT.RSA"));
        // System.arraycopy(d, 0, rsa, rsa.length - 256, 256);
        // FileUtils.writeByteArrayToFile(new File("src/test/resources/jar/META-INF/CERT.RSA"), rsa);
        // FileUtils.copyFile(new File("src/test/resources/a/CERT.SF"),
        // new File("src/test/resources/jar/META-INF/CERT.SF"));
        // FileUtils.copyFile(new File("src/test/resources/a/MANIFEST.MF"), new File(
        // "src/test/resources/jar/META-INF/MANIFEST.MF"));
    }
}
