package com.mybatis.lizx.model;


import org.apache.ibatis.type.Alias;

import java.io.Serializable;

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
    private String address;

    public Person() {
    }

    public Person(String name, int age, String phone, String email, String address) {
        this.name = name;
        this.age = age;
        this.phone = phone;
        this.email = email;
        this.address = address;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public int getAge() {
        return age;
    }

    public String getPhone() {
        return phone;
    }

    public String getEmail() {
        return email;
    }

    public String getAddress() {
        return address;
    }


    @Override
    public String toString() {
        return "Person{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", age=" + age +
                ", phone='" + phone + '\'' +
                ", email='" + email + '\'' +
                ", address='" + address + '\'' +
                '}';
    }

}
