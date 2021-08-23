package com.mybatis.lizx.model;


import org.apache.ibatis.type.Alias;

import java.io.Serializable;
import java.util.Date;

/**
 * @author lizx
 * @since 1.0.0
 * @note 开启二级缓存第三步、model类实现序列化，这一步是否非做不可有待研究
 **/
@Alias("person")
public class Person implements Serializable {

    private int id;
    private String name;
    private int age;
    private String phone;
    private String email;
    private Date createTime;
    private String address;

    public Person(String name, int age, String phone, String email, Date createTime, String address) {
        this.name = name;
        this.age = age;
        this.phone = phone;
        this.email = email;
        this.createTime = createTime;
        this.address = address;
    }

    public Person() {}

    @Override
    public String toString() {
        return "Person{" +
                "id=" + id +
                ", personName='" + name + '\'' +
                ", age=" + age +
                ", phone='" + phone + '\'' +
                ", email='" + email + '\'' +
                ", createTime=" + createTime +
                ", address='" + address + '\'' +
                '}';
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
}