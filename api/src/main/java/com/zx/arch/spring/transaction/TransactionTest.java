package com.zx.arch.spring.transaction;

import com.zx.arch.domain.entity.User;
import com.zx.arch.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author lizx
 * @date 2021/10/27
 * @since 普通类,没有接口
 **/
@Component
public class TransactionTest {

    @Autowired
    private UserService userService;

    /**
     * 事务的传播机制是什么？主要是当前方法是否能继承调用方的事务！换算到这里就是 a方法能否继承调用方的事务！如果调用方没有开启事务该怎么办？
     *
     * a方法不加事务，b方法加事务,a方法内调用 b方法，此时事务不会生效！  因为虽然spring会给TransactionTest生成代理对象(这个代理对象中只有b()方法做了代理)，但是a方法中调用的b还是原对象的方法 （原对象！=代理对象）
     * a方法加事务（传播机制为REQUIRED），b方法不加事务,a方法内调用 b方法，事务传播到b！ 此时a事务 （default）,虽然b没有事务，但是a有，她会直接加入 ！ a自己的调用方没有事务，但是传播机制为REQUIRED，所以会自己创建一个事务
     * a方法加事务（传播机制为SUPPORTS），b方法不加事务,a方法内调用 b方法，没有事务！ 此时a事务的事务传播为support,比较佛系，有就用，没有就不用事务了
     * a方法加事务（传播机制为MANDATORY），b方法不加事务,a方法内调用 b方法，没有事务！ 此时a事务的事务传播为MANDATORY,没有事务，所以直接抛出异常，里面的逻辑一个都执行不了
     * a方法加事务（传播机制为REQUIRES_NEW），b方法不加事务,a方法内调用 b方法，a事务传播到b！ 此时a事务的事务传播为REQUIRES_NEW,不管调用方有没有事务，都重新创建一个
     *a方法加事务（传播机制为REQUIRES_NEW），b加事务( Propagation.NOT_SUPPORTED),a方法内调用 b方法,a事务还是传播给了b， 此时a事务的事务传播为REQUIRES_NEW,不管调用方有没有事务，都重新创建一个,b的传播机制是NOT_SUPPORTED，意思就是不支持事务,但是a中调用的是原对象b,要解决这个问题，只能将b方法取出，放到其他类中
     *
     */
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void a(){
        User user = new User();
        user.setAge(18);
        user.setName("阿祥");
        userService.insert(user);

        b();

        int i = 1/0;
    }

//    @Transactional

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void b(){
        User user = new User();
        user.setId(1L);
        user.setName("小阿涂");
        user.setAge(17);
        userService.updateById(user);

        int i = 1/0;
    }

    /**
     *
     *     1、原对象的方法关键字使用不当也会导致代理失败 （事务不生效）
     *      基于接口代理(JDK代理)：类的方法非public修饰，或者用了static关键字修饰，无法代理
     *      基于CGLib代理(子类代理)：使用了private、static、final修饰，无法代理
     *
     *     2、在业务代码中如果抛出RuntimeException异常，事务回滚；但是抛出Exception，事务不回滚；
     *
     *     3、如果在加有事务的方法内，使用了try...catch..语句块对异常进行了捕获，而catch语句块没有throw new RuntimeExecption异常，事务也不会回滚
     *
     *
     *     4、如果采用spring+spring mvc，则context:component-scan重复扫描问题可能会引起事务失败。
     *
     *     下面这个得验证下：
     *
     * ​ 如果spring和mvc的配置文件中都扫描了service层，那么事务就会失效。
     * 原因：因为按照spring配置文件的加载顺序来讲，先加载springmvc配置文件，再加载spring配置文件，我们的事物一般都在srping配置文件中进行配置，
     * 如果此时在加载srpingMVC配置文件的时候，把servlce也给注册了，但是此时事物还没加载，也就导致后面的事物无法成功注入到service中。所以把对service的扫描放在spring配置文件
     */
    @Transactional()
    public void c(){
        User user = new User();
        user.setId(1L);
        user.setName("小阿涂");
        user.setAge(17);
        userService.updateById(user);

        int i = 1/0;
    }

    /**
     * 测试spring是怎么控制select的事物的 !
     *
     * 如果不加 @Transactional()，select查询都是自动提交的（使用mysql默认的autocommit）！然后单个select就是一个事务！所以如果两个相同select之间有另外的会话修改了，那两次查询结果是不一样的！
     * 如果加了@Transactional(),Spring会设置autocommit=0 ，然后自己管理事务,该方法中的所有查询都是同一个事务！能够保证两次查询一致！
     *
     * 所以如果一个方法中进行两次select,可能需要加事务的！因为要保证前后两次读取一致！
     * 比如对账！先查余额，再查订单，两次查询肯定是放到一个事务中去的,要不然可能不一致！
     */
    @Transactional
    public void test_select(){
        User userById = userService.getUserById(1L);

        System.out.println(userById);
        User userById1 = userService.getUserById(1L);

        System.out.println(userById1);
    }




}
