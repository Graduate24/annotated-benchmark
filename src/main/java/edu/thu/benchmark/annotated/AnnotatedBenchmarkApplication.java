package edu.thu.benchmark.annotated;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Spring Boot应用启动类
 * 使用现代的Spring Boot启动方式
 */
@SpringBootApplication
@EntityScan(basePackages = "edu.thu.benchmark.annotated.entity")
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class AnnotatedBenchmarkApplication extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(AnnotatedBenchmarkApplication.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(AnnotatedBenchmarkApplication.class, args);
    }
}
