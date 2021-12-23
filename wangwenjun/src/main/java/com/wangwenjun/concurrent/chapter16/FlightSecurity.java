package com.wangwenjun.concurrent.chapter16;

/***************************************
 * @author:Alex Wang
 * @Date:2017/11/26
 * QQ: 532500648
 * QQ群:463962286
 ***************************************/
public class FlightSecurity {
    private int count = 0;
    //登机牌
    private String boardingPass = "null";
    //身份证
    private String idCard = "null";

    /**
     * 单线程模式：排他的,每次只允许一个线程执行，最典型的实现就是synchronized
     * @param boardingPass
     * @param idCard
     */
    public synchronized void pass(String boardingPass, String idCard) {
        this.boardingPass = boardingPass;
        this.idCard = idCard;
        this.count++;
        check();
    }

    private void check() {
        if (boardingPass.charAt(0) != idCard.charAt(0)) {
            throw new RuntimeException("====Exception====" + toString());
        }
    }

    @Override
    public String toString() {
        return "The " + count + " passengers,boardingPass [" + boardingPass + "],idCard [" + idCard + "]";
    }
}
