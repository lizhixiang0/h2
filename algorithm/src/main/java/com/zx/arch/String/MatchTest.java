package com.zx.arch.String;

/**
 * @author lizx
 * @since 1.0.0
 * @description  简单模式匹配原则，说人话就是在主串中找到字串的位置
 **/
public class MatchTest {

    private static  char[] str = "gcccauajichasjhasjhasj".toCharArray();

     private static char[] sub = "ccas".toCharArray();

    public static void main(String[] args) {
        System.out.println(findStr());
    }

    public static int  findStr(){
        int point = 0,a = 0,b= 0;
        while (a<sub.length && b<str.length){
            if (sub[a]==str[b]){
                b+=1;
                a+=1;
            }else {
                point+=1;
                a=0;
                b=point;
            }
        }
        if (a>sub.length){
            return point;
        }else {
            return 0;
        }
    }


}
