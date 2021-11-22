package com.wangwenjun.concurrent.chapter03.fight;

import com.wangwenjun.concurrent.chapter03.fight.FightQuery;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author admin
 */
public class FightQueryTask extends Thread implements FightQuery {

    private final String origin;

    private final String destination;

    private final List<String> flightList = new ArrayList<>();

    public FightQueryTask(String airline, String origin, String destination) {
        super("[" + airline + "]");
        this.origin = origin;
        this.destination = destination;
    }

    /**
     * 顺便了解下ThreadLocalRandom
     * https://baijiahao.baidu.com/s?id=1658231674699407403&wfr=spider&for=pc
     * https://blog.csdn.net/u013115610/article/details/73527254
     * https://www.jianshu.com/p/89dfe990295c
     */
    @Override
    public void run() {
        System.out.printf("%s-query from %s to %s \n", getName(), origin, destination);
        int randomVal = ThreadLocalRandom.current().nextInt(10);
        try
        {
            TimeUnit.SECONDS.sleep(randomVal);
            this.flightList.add(getName() + "-" + randomVal);
            System.out.printf("The Fight:%s list query successful\n", getName());
        } catch (InterruptedException e) {
        }
    }

    @Override
    public List<String> get() {
        return this.flightList;
    }
}
