package pxb.android.tinysign.gen;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import org.apache.commons.codec.binary.Base64;

public abstract class PrivateKey {

    /**
     * @param args
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Expected args: <Keystore file> <Keystore password> <alias> <key password>");
            return;
        }
        String keystoreName = args[0];
        String keystorePassword = args[1];
        String alias = args[2];
        String keyPassword = args[3];

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream(keystoreName), keystorePassword.toCharArray());
        Key key = keystore.getKey(alias, keyPassword.toCharArray());
        String string = new String(Base64.encodeBase64(key.getEncoded()), "iso-8859-1");
        System.out.println(string);
    }
}
