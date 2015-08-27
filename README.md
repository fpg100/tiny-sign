# tiny-sign
Automatically exported from code.google.com/p/tiny-sign

create a signed jar in quick way.

It can run directly on android devices.

Here is an example

  // sign asset/unsigned.apk and install it
  public void a(Context ctx, File orgJar) {
    // create a tmp dir for extract content in unsigend.jar
    final File dir = ctx.getDir("tmp", Context.MODE_PRIVATE);
    InputStream in = ctx.getAssets().open("unsigned.apk");
    // do extract to tmp dir
    extract(in, dir);
    in.close();
    File distFile = ctx.getFileStreamPath("signed.apk");
    FileOutputStream fos = new FileOutputStream(distFile);
    // do sign
    TinySign.sign(dir, fos); 
    fos.close();
    // install it
    Intent promptInstall = new Intent(Intent.ACTION_VIEW);
    promptInstall.setDataAndType(Uri.fromFile(distFile), "application/vnd.android.package-archive");
    ctx.startActivity(promptInstall);
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
