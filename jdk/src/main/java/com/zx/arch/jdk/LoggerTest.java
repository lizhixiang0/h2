package com.zx.arch.jdk;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;


/**
 * @author lizx
 * @since 1.0.0
 * @description  使用log的注意点
 **/

@Slf4j
public class LoggerTest {
    @Getter
    @Setter
    @AllArgsConstructor
    static class Message{
        private String value1;
        private String value2;

        @Override
        public String toString() {
            return value2+value1;
        }
    }

    /**
     * Method explicitly calls toString() on a logger parameter
     * 使用参数化的日志记录时,不要用toString方法
     */
    public static void a(){
        log.info("test the logger {}",new Message("a","b"));
        log.info("test the logger {}",new Message("a","b").toString());  //不推荐，多此一举并且容易导致NPP
    }

    public static void main(String[] args) {
        a();
    }
}
