package com.zx.arch.spring.annotation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * @author lizx
 * @since 1.0.0
 * @description 条件注解
 * @link   "https://blog.csdn.net/qq_38366063/article/details/93913053
 * @note 使用kafka麻烦的一比，必须在本地启动,给我改的没辙了
 **/
@ConditionalOnBean
@ConditionalOnProperty
//@Conditional({MessageEngineConditions.InMemoryEnabledCondition.class})
public class ConditionTest {
}
