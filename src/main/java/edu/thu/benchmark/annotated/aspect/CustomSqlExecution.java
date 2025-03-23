package edu.thu.benchmark.annotated.aspect;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 自定义SQL执行注解
 * 用于标记需要通过切面执行的SQL语句
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface CustomSqlExecution {

    /**
     * SQL语句，可以包含 :paramName 形式的参数占位符
     */
    String sql();

    /**
     * 参数名称数组，按顺序对应方法参数
     */
    String[] paramNames();

    /**
     * 是否安全执行，为false时使用不安全的字符串拼接方式
     */
    boolean safe() default false;
}
