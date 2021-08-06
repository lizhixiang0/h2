package com.zx.arch.guava.predicates;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * @author lizx
 * @since 1.0.0
 * @description 这个工具类。。。
 **/
public class PredicatesTest {
    static List<User>  users = new ArrayList<>();
    static {
        users.add(new User("chang",24));
        users.add(new User("chen",26));
        users.add(new User("sun",24));
    }

    /**
     * 配合Chrome的Iterables.filter()进行过滤
     */
    private static void test(){
        //保留age不为26的User
        Predicate<User> predicate1 = user -> user.getAge() != 26;

        //与predicate1条件相反
        Predicate<User> notpredicate1 = Predicates.not(predicate1);

        //保留userName 是 chang 的user
        Predicate<User> predicate2 = user -> Objects.equals(user.getUserName(),"chang");
        //保留age不为 26 以及 userName 是 chang 的User
        Predicate<User> predicate1_and_predicate2 = Predicates.and(predicate1, predicate2::test);
        //保留age不为26 或 userName 是 chang的User
        Predicate<User> predicate1_or_predicate2 = Predicates.or(predicate1, predicate2::test);


        List<User> filteredUsers1 = Lists.newArrayList(Iterables.filter(users,predicate1));
        List<User> filteredUsersNot1 = Lists.newArrayList(Iterables.filter(users,notpredicate1));

        List<User> filteredUsers2 = Lists.newArrayList(Iterables.filter(users, predicate2::test));
        List<User> filteredUsers1and2 = Lists.newArrayList(Iterables.filter(users,predicate1_and_predicate2));
        List<User> filteredUsers1or2 = Lists.newArrayList(Iterables.filter(users,predicate1_or_predicate2));



        System.out.println("result size for filteredUsers1: " + filteredUsers1.size());          //2->  chang sun
        System.out.println("result size for filteredUsers2:  " + filteredUsers2.size());         //1-> chang
        System.out.println("result size for filteredUsers1and2:  " + filteredUsers1and2.size()); //1-> chang
        System.out.println("result size for filteredUsers1or2:  " + filteredUsers1or2.size());   //2-> chang sun

        System.out.println("result size for filteredUsersNot1:  " + filteredUsersNot1.size());   //1-> chen
    }

    public static void main(String[] args) {
        test();
    }

}

@Data
@AllArgsConstructor
class User {
    private String userName;
    private int age;
}
