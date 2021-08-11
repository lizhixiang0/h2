package com.zx.arch.unzip;

import com.github.junrar.Archive;
import com.github.junrar.UnrarCallback;
import com.github.junrar.exception.RarException;
import com.github.junrar.rarfile.FileHeader;
import com.github.junrar.volume.Volume;
import net.sf.sevenzipjbinding.IInArchive;
import net.sf.sevenzipjbinding.SevenZip;
import net.sf.sevenzipjbinding.SevenZipException;
import net.sf.sevenzipjbinding.impl.RandomAccessFileInStream;

import java.io.*;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description "https://blog.csdn.net/weixin_42418785/article/details/90344053
 **/
public class UnRarUtils {

    private final  static String rarFileName = "D:\\JetBrains\\workspace\\h2\\api\\src\\test\\java\\com\\zx\\arch\\unzip\\test.rar";
    private final  static String outFilePath = "D:\\JetBrains\\workspace\\h2\\api\\src\\test\\java\\com\\zx\\arch\\unzip\\";

    /**
     * winrar5.0���°汾��ѹ
     * @param rarFileName rar file name
     * @param outFilePath output file path
     * @param callback    callback
     * @throws Exception
     * @author shijian
     */
    public static void unrar(String rarFileName, String outFilePath, UnrarCallback callback) throws Exception {
        Archive archive = new Archive(new File(rarFileName), callback);
        if (archive == null) {
            throw new FileNotFoundException(rarFileName + " NOT FOUND!");
        }
        if (archive.isEncrypted()) {
            throw new Exception(rarFileName + " IS ENCRYPTED!");
        }
        List<FileHeader> files = archive.getFileHeaders();
        for (FileHeader fh : files) {
            if (fh.isEncrypted()) {
                throw new Exception(rarFileName + " IS ENCRYPTED!");
            }
            String fileName = fh.getFileNameString();
            if (fileName != null && fileName.trim().length() > 0) {
                String saveFileName = outFilePath + File.separator + fileName;
                File saveFile = new File(saveFileName);
                File parent = saveFile.getParentFile();
                if (!parent.exists()) {
                    parent.mkdirs();
                }
                if (!saveFile.exists()) {
                    saveFile.createNewFile();
                }
                FileOutputStream fos = new FileOutputStream(saveFile);
                try {
                    archive.extractFile(fh, fos);
                } catch (RarException e) {
                    throw e;
                } finally {
                    try {
                        fos.flush();
                        fos.close();
                    } catch (Exception e) {
                    }
                }
            }
        }
    }

    public static void test() throws Exception {
        UnRarUtils.unrar(rarFileName, outFilePath, new UnrarCallback() {
            int currentProgress = -1;

            @Override
            public boolean isNextVolumeReady(Volume volume) {
                return true;
            }

            @Override
            public void volumeProgressChanged(long l, long l1) {
                int progress = (int) ((double) l / l1 * 100);
                if (currentProgress != progress) {
                    currentProgress = progress;
                    System.out.println(currentProgress);
                }
            }
        });
    }

    /**
     * java��ѹrar5 ����rar4
     * https://blog.csdn.net/qq974816077/article/details/115384443
     */
    public static void test2(String password) throws SevenZipException, FileNotFoundException {
        RandomAccessFile randomAccessFile;
        IInArchive inArchive;

        // ��һ����������Ҫ��ѹ��ѹ����·�����ڶ��������ο�JdkAPI�ĵ���RandomAccessFile
        randomAccessFile = new RandomAccessFile(rarFileName, "r");
        inArchive = SevenZip.openInArchive(null, new RandomAccessFileInStream(randomAccessFile));

        int[] in = new int[inArchive.getNumberOfItems()];
        for (int i = 0; i < in.length; i++) {
            in[i] = i;
        }
        inArchive.extract(in, false, new ExtractCallback(inArchive, password,outFilePath));

    }

    /**
     * ���������з�ʽ��ѹ�ļ�
     * �����ļ����þ���·��
     * @blog "https://www.cnblogs.com/fetty/p/4769279.html
     * @param rarFilePath ѹ���ļ�·��+�ļ���
     * @param destDir     ��ѹ���·��
     * @param password
     * @note Winrar ��������ѹ��һ���ļ� ������ https://blog.csdn.net/Open2ye/article/details/615077  winrar a 2.rar 2.txt -p1  1��������
     * @return
     */
    public static void unRar(String rarFilePath, String destDir, String password) throws Exception {
        File rarFile = new File(rarFilePath);
        // ��ʼ���������н�ѹ������-o+�Ǳ�ʾ���ǵ���˼
        String cmdPath = "F:\\WinRAR\\WinRAR.exe";
        //  String cmdPath = "/usr/local/bin/unrar"; ���linux��������������Ҫ����·��
        String cmd = cmdPath + " X -o+ " + rarFile + " " + destDir + " -p"+password + " -y";
        Runtime.getRuntime().exec(cmd);
    }

    /**
     * 1�����������ַ����������������
     * 2�����������ַ���������
     */
    private static void fullPermutation(String s) throws Exception {
        permutation(s.toCharArray(),0,s.length()-1);

    }
    private static void permutation(char[] c, int start, int end) throws Exception {
        if(start==end){
            //unRar(rarFileName,outFilePath,new String(c));
            System.out.println(c);
            test2(new String(c));
        }
        else {
            for(int i=start;i<=end;i++) {
                if(i!=start && c[i]!=c[start] || i==start) {  //��ֹ�ظ�
                    swap(c,i,start);
                    permutation(c,start+1,end);    //�����������
                    swap(c,i,start);
                }
            }
        }

    }

    private static void swap(char[] c, int i, int start) {
        char temp=c[i];
        c[i]=c[start];
        c[start]=temp;

    }


    /**
     * �г��ַ����������Ӵ�
     * abc
     * @param s
     * @throws Exception
     */
    public static void list(String s) throws Exception {
        for (int i=0;i<s.length();i++){
            for (int j = i+1;j<=s.length();j++){
                fullPermutation(s.substring(i, j));
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // test();
        //test2("123456");
        list("0123456");
    }


}
