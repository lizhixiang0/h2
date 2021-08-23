package com.zx.arch.unzip;


import net.sf.sevenzipjbinding.*;

import java.io.*;

public class ExtractCallback implements IArchiveExtractCallback , ICryptoGetTextPassword{

    private IInArchive inArchive;
    private String ourDir;
    private String password;

    public ExtractCallback(IInArchive inArchive, String password,String ourDir) {
        this.inArchive = inArchive;
        this.ourDir = ourDir;
        this.password = password;
    }

    @Override
    public void setCompleted(long arg0) {
    }

    @Override
    public void setTotal(long arg0) {
    }

    @Override
    public ISequentialOutStream getStream(int index, ExtractAskMode extractAskMode) throws SevenZipException {
        final String path = (String) inArchive.getProperty(index, PropID.PATH);
        final boolean isFolder = (boolean) inArchive.getProperty(index, PropID.IS_FOLDER);
        return data -> {
            try {
                if (!isFolder) {
                    System.out.println(path);
                    File file = new File(ourDir + path);
                    save2File(file, data);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return data.length;
        };
    }

    @Override
    public void prepareOperation(ExtractAskMode arg0) {
    }

    @Override
    public void setOperationResult(ExtractOperationResult extractOperationResult) {
    }

    public static boolean save2File(File file, byte[] msg) {
        OutputStream fos = null;
        try {
            File parent = file.getParentFile();
            if ((!parent.exists()) && (!parent.mkdirs())) {
                return false;
            }
            fos = new FileOutputStream(file);
            fos.write(msg);
            fos.flush();
            return true;
        } catch (FileNotFoundException e) {
            return false;
        } catch (IOException e) {
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                }
            }
        }
    }

    @Override
    public String cryptoGetTextPassword() {
        return this.password;
    }
}
