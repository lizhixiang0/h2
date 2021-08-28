package com.zx.arch.leetcode.string;

import org.springframework.util.StringUtils;

/**
 * @author lizx
 * @date 2021/8/20
 * @description
 * 给定一个字符串 s 和一个整数 k，从字符串开头算起，每 2k 个字符反转前 k 个字符。
 *
 * 如果剩余字符少于 k 个，则将剩余字符全部反转。
 * 如果剩余字符小于 2k 但大于或等于 k 个，则反转前 k 个字符，其余字符保持原样。
 *  
 *
 * 示例 1：
 *
 * 输入：s = "abcdefg", k = 2
 * 输出："bacdfeg"
 * 示例 2：
 *
 * 输入：s = "abcd", k = 2
 * 输出："bacd"
 *  
 *
 * 提示：
 *
 * 1 <= s.length <= 10000
 * s 仅由小写英文组成
 * 1 <= k <= 10000
 *
 * 链接：https://leetcode-cn.com/problems/reverse-string-ii
 *
 **/
public class ReverseString {
    /**
     *  1、反转怎么实现
     *  2、每2k个一组!最后一组不满2k另外考虑!
     *  3、临界值,k=1直接返回s,s为空直接返回
     *
     *  我的解法就是,每隔2k个反转k个，末尾额外判断。
     *  简单易懂 ！O(n)
     * @param s
     * @param k
     * @return
     */
//    private static String reverseStr(String s, int k){
//        char[] chars =s.toCharArray();
//        if (k<=1 || StringUtils.isEmpty(s)){
//            return s;
//        }else {
//            int num = 1;
//            int point  = 2*k*num;
//            // abcd efghi
//            while (point<s.length()){
//                reverse(chars,point-2*k,point-k-1);
//                num+=1;
//                point = 2*k*num;
//            }
//
//            int surplus = chars.length - 2*k*(num-1);
//            point = 2*k*(num-1);
//            if (surplus<k){
//                reverse(chars,point,chars.length-1);
//            }else {
//                reverse(chars,point,point+k-1);
//            }
//        }
//        return new String(chars);
//    }
//
//    /**
//     * abcdefg
//     *    。  。
//     *    3   6
//     *     45
//     * @param chars
//     * @param start
//     * @param end
//     * @return
//     */
//    private static char[] reverse(char[] chars,int start , int end){
//        int limit = (start + end)/2;
//        for (int i = start; i <=limit; i++) {
//            char temp = chars[start];
//            chars[start] = chars[end];
//            chars[end] = temp;
//
//            start+=1;
//            end-=1;
//        }
//        return chars;
//    }

//    public static void main(String[] args) {
//        System.out.println(reverseStr("abcdefg",8));
//    }

    /**
     * 这个解法叫什么双指针
     * @param s
     * @param k
     * @return
     */
    public String reverseStr(String s, int k) {

        // 计算反转次数
        int n = 2 * k;
        int c = s.length() / n;

        char[] arr = s.toCharArray();

        for (int i = 0; i <= c; i++) {

            // 计算每次反转开始结束位置
            int left = i * n;
            int right = i * n + k - 1;

            // 防治数组越界
            if(right > arr.length - 1){
                right = arr.length - 1;
            }

            // 双指针
            while(left < right){
                char temp = arr[left];
                arr[left] = arr[right];
                arr[right] = temp;
                left++;
                right--;
            }
        }

        return new String(arr);
    }


}
