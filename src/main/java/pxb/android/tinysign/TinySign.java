/*
 * Copyright (c) 2009-2012 Panxiaobo
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pxb.android.tinysign;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestOutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

/**
 * create a signed jar in quick way
 * 
 * @author <a href="mailto:pxb1988@gmail.com">Panxiaobo</a>
 * 
 */
public class TinySign {

    /** Write to another stream and also feed it to the Signature object. */
    private static class SignatureOutputStream extends FilterOutputStream {
        private Signature mSignature;

        public SignatureOutputStream(OutputStream out, Signature sig) {
            super(out);
            mSignature = sig;
        }

        public void write(byte buffer[]) throws IOException {
            try {
                mSignature.update(buffer);
            } catch (SignatureException e) {
                throw new IOException("SignatureException: " + e);
            }
            out.write(buffer);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                mSignature.update(b, off, len);
            } catch (SignatureException e) {
                throw new IOException("SignatureException: " + e);
            }
            out.write(b, off, len);
        }

        @Override
        public void write(int b) throws IOException {
            try {
                mSignature.update((byte) b);
            } catch (SignatureException e) {
                throw new IOException("SignatureException: " + e);
            }
            out.write(b);
        }
    }

    private static byte[] dBase64(String data) throws UnsupportedEncodingException {
        return Base64.decodeBase64(data.getBytes("UTF-8"));
    }

    private static void doDir(String prefix, File dir, ZipOutputStream zos, DigestOutputStream dos, Manifest m)
            throws IOException {
        zos.putNextEntry(new ZipEntry(prefix));
        zos.closeEntry();
        for (File f : dir.listFiles()) {
            if (f.isFile()) {
                doFile(prefix + f.getName(), f, zos, dos, m);
            } else {
                doDir(prefix + f.getName() + "/", f, zos, dos, m);
            }
        }
    }

    private static void doFile(String name, File f, ZipOutputStream zos, DigestOutputStream dos, Manifest m)
            throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        FileInputStream fis = FileUtils.openInputStream(f);
        IOUtils.copy(fis, dos);
        IOUtils.closeQuietly(fis);
        byte[] digets = dos.getMessageDigest().digest();
        zos.closeEntry();
        Attributes attr = new Attributes();
        attr.putValue("SHA1-Digest", eBase64(digets));
        m.getEntries().put(name, attr);
    }

    private static String eBase64(byte[] data) {
        return new String(Base64.encodeBase64(data));
    }

    private static Manifest generateSF(Manifest manifest) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        PrintStream print = new PrintStream(new DigestOutputStream(new OutputStream() {

            @Override
            public void write(byte[] arg0) throws IOException {
            }

            @Override
            public void write(byte[] arg0, int arg1, int arg2) throws IOException {
            }

            @Override
            public void write(int arg0) throws IOException {
            }
        }, md), true, "UTF-8");
        Manifest sf = new Manifest();
        Map<String, Attributes> entries = manifest.getEntries();
        for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
            // Digest of the manifest stanza for this entry.
            print.print("Name: " + entry.getKey() + "\r\n");
            for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
                print.print(att.getKey() + ": " + att.getValue() + "\r\n");
            }
            print.print("\r\n");
            print.flush();

            Attributes sfAttr = new Attributes();
            sfAttr.putValue("SHA1-Digest", eBase64(md.digest()));
            sf.getEntries().put(entry.getKey(), sfAttr);
        }
        return sf;
    }

    private static Signature instanceSignature() throws Exception {
        byte[] data = dBase64(Constants.privateKey);
        KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = rSAKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        return signature;
    }

    /**
     * create a signed jar from dir to out
     * 
     * @param dir
     *            a folder contains file
     * @param out
     *            the output jar
     * @throws Exception
     */
    public static void sign(File dir, OutputStream out) throws Exception {
        ZipOutputStream zos = new ZipOutputStream(out);
        zos.putNextEntry(new ZipEntry("META-INF/"));
        zos.closeEntry();
        // .MF
        Manifest manifest = new Manifest();
        String sha1Manifest = writeMF(dir, manifest, zos);

        // SF
        Manifest sf = generateSF(manifest);
        byte[] sign = writeSF(zos, sf, sha1Manifest);

        writeRSA(zos, sign);
        IOUtils.closeQuietly(zos);
    }

    private static String writeMF(File dir, Manifest manifest, ZipOutputStream zos) throws NoSuchAlgorithmException,
            IOException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        DigestOutputStream dos = new DigestOutputStream(zos, md);
        zipAndSha1(dir, zos, dos, manifest);
        Attributes main = manifest.getMainAttributes();
        main.putValue("Manifest-Version", "1.0");
        main.putValue("Created-By", "tiny-sign-" + TinySign.class.getPackage().getImplementationVersion());
        zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
        manifest.write(dos);
        zos.closeEntry();
        return eBase64(md.digest());
    }

    private static void writeRSA(ZipOutputStream zos, byte[] sign) throws IOException {
        zos.putNextEntry(new ZipEntry("META-INF/CERT.RSA"));
        zos.write(dBase64(Constants.sigPrefix));
        zos.write(sign);
        zos.closeEntry();
    }

    private static byte[] writeSF(ZipOutputStream zos, Manifest sf, String sha1Manifest) throws Exception {
        Signature signature = instanceSignature();
        zos.putNextEntry(new ZipEntry("META-INF/CERT.SF"));
        SignatureOutputStream out = new SignatureOutputStream(zos, signature);
        out.write("Signature-Version: 1.0\r\n".getBytes("UTF-8"));
        out.write(("Created-By: tiny-sign-" + TinySign.class.getPackage().getImplementationVersion() + "\r\n")
                .getBytes("UTF-8"));
        out.write("SHA1-Digest-Manifest: ".getBytes("UTF-8"));
        out.write(sha1Manifest.getBytes("UTF-8"));
        out.write('\r');
        out.write('\n');

        sf.write(out);

        zos.closeEntry();

        return signature.sign();
    }

    private static void zipAndSha1(File dir, ZipOutputStream zos, DigestOutputStream dos, Manifest m)
            throws NoSuchAlgorithmException, IOException {
        for (File f : dir.listFiles()) {
            if (!f.getName().startsWith("META-INF")) {
                if (f.isFile()) {
                    doFile(f.getName(), f, zos, dos, m);
                } else {
                    doDir(f.getName() + "/", f, zos, dos, m);
                }
            }
        }
    }
}
