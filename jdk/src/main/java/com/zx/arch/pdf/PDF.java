package com.zx.arch.pdf;

/**
 * @author lizx
 * @date 2021/11/16
 * @since
 * @blog “https://blog.csdn.net/a1035127752/article/details/78350930
 **/
import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lowagie.text.Chapter;
import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Section;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfWriter;
import com.lowagie.text.pdf.draw.DottedLineSeparator;

public class PDF {

    public static void main(String[] args) throws Exception {

        Document doc = new Document(PageSize.A4, 48, 48, 60, 65);
        PdfWriter contentWriter = PdfWriter.getInstance(doc, new ByteArrayOutputStream());
        //设置事件
        ContentEvent event = new ContentEvent();
        contentWriter.setPageEvent(event);

        //存目录监听 开始
        doc.open();
        List<Chapter> chapterList = new ArrayList<Chapter>();

        //根据chapter章节分页
        for (int i = 1; i <= 3; i++) {
            Chapter chapter = new Chapter(new Paragraph("第"+ i +"单元  ",setFont(18f)),i);
            for (int j = 0; j < 3; j++) {
                Section section = chapter.addSection(new Paragraph("第" + (j + 1)+"节",setFont(16f)));
                section.setIndentationLeft(10);
                section.add(new Paragraph("\n"));
                for (int k = 0; k < 4; k++) {
                    Section subSection = section.addSection(new Paragraph("第" + (k + 1) +"题",setFont(12f)));
                    subSection.setIndentationLeft(10);
                    Paragraph paragraph = new Paragraph("\n2017年8月17日，LIGO和Virgo在4000万秒差距（1.3亿光年）之外的NGC\n 4993星系内首次探测到了两颗中子星的合并\n",setFont(10f));

                    Image image = Image.getInstance("https://gss0.bdstatic.com/5bVWsj_p_tVS5dKfpU_Y_D3/res/r/image/2017-09-27/297f5edb1e984613083a2d3cc0c5bb36.png");
                    image.setAlignment(Image.ALIGN_CENTER);
                    image.scaleAbsolute(300, 100);// 直接设定显示尺寸

                    PdfPTable table = createTable(1);
                    table.addCell(createCell(paragraph));
                    table.addCell(createCell(image));

                    subSection.add(table);
                }
            }

            doc.add(chapter);
            chapterList.add(chapter); //保存章节内容

        }

        doc.close();
        //存目录监听 结束

        Document document = new Document(PageSize.A4, 48, 48, 60, 65);
        String path = "test.pdf";
        String dir = "E://TEST";
        File file = new File(dir);
        if (!file.exists()) {
            file.mkdir();
        }
        path = dir + File.separator + path;
        FileOutputStream os = new FileOutputStream(path);
        PdfWriter writer = PdfWriter.getInstance(document, os);
        IndexEvent indexEvent = new IndexEvent();
        writer.setPageEvent(indexEvent);
        document.open();

        //添加章节目录
        Chapter indexChapter = new Chapter(new Paragraph("目录：", setFont(20f)), 0);
        indexChapter.setNumberDepth(-1);                              // 设置数字深度
        for (Map.Entry<String, Integer> index : event.index.entrySet()) {
            String key = index.getKey();
            String keyValue = key;
            float size = 18f;
            if (countInString(key, ".") == 2) { //小标题缩进判断, 如有三级标题自己添加判断
                keyValue = "    " + key;
                size = 15f;
            } else if (countInString(key, ".") == 3) {
                keyValue = "    " + "    " + key;
                size = 12f;
            }
            Paragraph paragraph = new Paragraph(keyValue,setFont(size));

            Chunk chunk0101 = new Chunk(new DottedLineSeparator());

            Chunk pageno = new Chunk(index.getValue() + "");

            Chunk chunk0102 = new Chunk(pageno);

            //加入点点
            paragraph.add(chunk0101);
            //加入页码
            paragraph.add(chunk0102);

            indexChapter.add(paragraph);
        }

        document.add(indexChapter);

        document.newPage();

        //添加内容
        for (Chapter c : chapterList) {
            indexEvent.body = true;
            document.add(c);
        }

        document.close();
        os.close();
    }


    //根据目录编号的长度判断菜单的等级   例：1.1.1.  长度为3
    public static int countInString(String str1, String str2) {
        int total = 0;
        for (String tmp = str1; tmp != null && tmp.length() >= str2.length();){
            if(tmp.indexOf(str2) == 0){
                total++;
                tmp = tmp.substring(str2.length());
            }else{
                tmp = tmp.substring(1);
            }
        }
        return total;
    }


    //页码监听
    private static class ContentEvent extends PdfPageEventHelper {

        private int page;
        Map<String, Integer> index = new LinkedHashMap<String, Integer>();

        @Override
        public void onStartPage (PdfWriter writer, Document document) {
            page++;
        }

        @Override
        public void onChapter (PdfWriter writer, Document document, float paragraphPosition, Paragraph title) {
            index.put(title.getContent(), page);
        }

        @Override
        public void onSection (PdfWriter writer, Document document, float paragraphPosition, int depth, Paragraph title) {
            onChapter(writer, document, paragraphPosition, title);
        }
    }

    //根据页码加页脚
    private static class IndexEvent extends PdfPageEventHelper {

        private int page;
        private boolean body;
        @Override
        public void onEndPage (PdfWriter writer, Document document) {
            if (body) {
                page++;
                //设置页脚页码
                //页码是奇数在右边，偶数在左边
                float x = page%2 == 0 ? document.left()-20 : document.right()+20;
                ColumnText.showTextAligned(writer.getDirectContent(), Element.ALIGN_CENTER, new Phrase(page + ""),
                        x, document.bottom() - 40, 0);
            }
        }
    }

    //设置字体
    public static Font setFont(Float fontsize){
        Font font = new Font();
        try {
            BaseFont bfComic = BaseFont.createFont("c:\\windows\\fonts\\simkai.ttf",
                    BaseFont.IDENTITY_H, BaseFont.NOT_EMBEDDED);
            font = new Font(bfComic, fontsize, Font.NORMAL,Color.BLACK);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return font;
    }
    //创建表格
    public static PdfPTable createTable(int colume){
        PdfPTable table = new PdfPTable(colume);
        table.setHorizontalAlignment(Element.ALIGN_CENTER);
        table.setTotalWidth(400);
        table.setLockedWidth(true);
        table.getDefaultCell().setBorder(0);
        return table;
    }
    //创建单元格
    public static PdfPCell createCell(Element element){
        PdfPCell cell = new PdfPCell();
        cell.setHorizontalAlignment(Element.ALIGN_RIGHT);
        cell.setBorderWidth(0);
        cell.addElement(element);
        return cell;
    }
}