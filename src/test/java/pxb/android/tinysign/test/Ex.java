package pxb.android.tinysign.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public abstract class Ex {

    public static void main(String... args) throws IOException {
        File dir = new File("target/tmp");
        File jar = new File("src/test/resources/a.jar");
        File jar2 = new File("target/b.jar");
        // FileUtils.cleanDirectory(dir);
        {
            FileInputStream fis = FileUtils.openInputStream(jar);
            extract(fis, dir);
            IOUtils.closeQuietly(fis);
        }
    }

    public static void extract(InputStream in, File dir) throws IOException {
        ZipInputStream zis = new ZipInputStream(in);
        for (ZipEntry e = zis.getNextEntry(); e != null; e = zis.getNextEntry()) {
            String name = e.getName();
            if (!e.isDirectory()) {
                FileOutputStream fos = FileUtils.openOutputStream(new File(dir, name));
                IOUtils.copy(zis, fos);
                IOUtils.closeQuietly(fos);
            }
        }
    }

}
