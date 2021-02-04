package org.apache.ibatis.submitted.custom_collection_handling;

import java.util.List;

import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.factory.ObjectFactory;
import org.apache.ibatis.reflection.property.PropertyTokenizer;

public class CustomObjectWrapper implements org.apache.ibatis.reflection.wrapper.ObjectWrapper {

  private CustomCollection collection;

  public CustomObjectWrapper(CustomCollection collection){
    this.collection = collection;
  }

  @Override
  public Object get(PropertyTokenizer prop) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void set(PropertyTokenizer prop, Object value) {
    // TODO Auto-generated method stub

  }

  @Override
  public String findProperty(String name, boolean useCamelCaseMapping) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String[] getGetterNames() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String[] getSetterNames() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Class<?> getSetterType(String name) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Class<?> getGetterType(String name) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean hasSetter(String name) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public boolean hasGetter(String name) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public MetaObject instantiatePropertyValue(String name, PropertyTokenizer prop, ObjectFactory objectFactory) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean isCollection() {
    return true;
  }

  @Override
  public void add(Object element) {
    ((CustomCollection<Object>) collection).add(element);
  }

  @Override
  public <E> void addAll(List<E> element) {
    ((CustomCollection<Object>) collection).addAll(element);
  }

}
