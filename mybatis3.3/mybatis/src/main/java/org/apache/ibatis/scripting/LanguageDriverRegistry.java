/*
 * Copyright 2012 MyBatis.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ibatis.scripting;

import java.util.HashMap;
import java.util.Map;

/**
 * 脚本语言注册器
 * @author Frank D. Martinez [mnesarco]
 */
public class LanguageDriverRegistry {

  private final Map<Class<?>, LanguageDriver> LANGUAGE_DRIVER_MAP = new HashMap<>();

  private Class<?> defaultDriverClass = null;

  public void register(Class<?> cls) {
    if (cls == null) {
      throw new IllegalArgumentException("null is not a valid Language Driver");
    }
    if (!LanguageDriver.class.isAssignableFrom(cls)) {
      throw new ScriptingException(cls.getName() + " does not implements " + LanguageDriver.class.getName());
    }
    //如果没注册过，再去注册
    LanguageDriver driver = LANGUAGE_DRIVER_MAP.get(cls);
    if (driver == null) {
      try {
        //单例模式，即一个Class只有一个对应的LanguageDriver
        driver = (LanguageDriver) cls.newInstance();
        LANGUAGE_DRIVER_MAP.put(cls, driver);
      } catch (Exception ex) {
        throw new ScriptingException("Failed to load language driver for " + cls.getName(), ex);
      }
    }
  }

  public LanguageDriver getDriver(Class<?> cls) {
    return LANGUAGE_DRIVER_MAP.get(cls);
  }

  public LanguageDriver getDefaultDriver() {
    return getDriver(getDefaultDriverClass());
  }

  public Class<?> getDefaultDriverClass() {
    return defaultDriverClass;
  }

  /**
   * Configuration的无参构造调用，默认的为XMLLanguageDriver
   * @param defaultDriverClass  语言驱动
   */
  public void setDefaultDriverClass(Class<?> defaultDriverClass) {
    register(defaultDriverClass);
    this.defaultDriverClass = defaultDriverClass;
  }

}
