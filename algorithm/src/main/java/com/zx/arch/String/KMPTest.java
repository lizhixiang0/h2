package com.zx.arch.String;

/**
 * @author lizx
 * @description kmp算法
 * @since 1.0.0
 **/
public class KMPTest {
    private static char[] str = "BBC ABCDAB ABCDABCDABDE".toCharArray();

    private static char[] sub = "ABCDABD".toCharArray();

    private static int[] next = {0, 0, 0, 0, 0, 1, 2};

    public static int findStr() {
        int a = 0, b = 0;
        while (a < sub.length && b < str.length) {
            if (sub[a] == str[b]) {
                b += 1;
                a += 1;
            } else if (a == 0) {
                b += 1;
            } else {
                a = next[a];
            }
        }
        if (a >= sub.length) {
            return b - sub.length;
        } else {
            return 0;
        }
    }

    /**  0 1 2 3 4 5 6
     *   A B C D A B D
     * { 0,0,0,0,0,1,2}
     *
     * @return
     */
    public static int[] findNextArr(char[] chars) {
        int[] next = new int[chars.length];
        // next数组第一个位置和第二个位置永远是0
        int j = 0;
        next[0] = j;
        next[1] = j;
        int i = 2;
        while (i < chars.length) {
            if (chars[i-1]==chars[j]){
                next[i++] = ++j;
            }else if (j==0){
                i++;
            }else {
                /*这个地方的精髓在于,next数组中存储的既是下一次要跳转的位置，同时也是这一次前后缀匹配不上，回退的位置*/
                j = next[j];
            }
        }
        return next;
    }

    public static void main(String[] args) {

    }
}
