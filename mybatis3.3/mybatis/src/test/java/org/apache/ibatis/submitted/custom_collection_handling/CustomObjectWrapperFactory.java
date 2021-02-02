package org.apache.ibatis.submitted.custom_collection_handling;

import org.apache.ibatis.reflection.MetaObject;
import org.apache.ibatis.reflection.wrapper.ObjectWrapper;

public class CustomObjectWrapperFactory implements org.apache.ibatis.reflection.wrapper.ObjectWrapperFactory {

  @Override
  public boolean hasWrapperFor(Object object) {
    return object.getClass().equals(CustomCollection.class);
  }

  @Override
  public ObjectWrapper getWrapperFor(MetaObject metaObject, Object object) {
    return new org.apache.ibatis.submitted.custom_collection_handling.CustomObjectWrapper((CustomCollection) object);
  }

}
