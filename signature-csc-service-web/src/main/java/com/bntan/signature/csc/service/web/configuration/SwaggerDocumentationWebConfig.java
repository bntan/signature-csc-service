package com.bntan.signature.csc.service.web.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerDocumentationWebConfig {

    ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Signature CSC service")
                .description("Signature CSC service REST API description. This service is used to sign PDF documents using underlying CSC signature server.")
                .version("1.0.0")
                .contact(new Contact("Bun-Ny TAN", "https://www.bntan.com", "me@bntan.com"))
                .build();
    }

    @Bean()
    public Docket webImplementation() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.regex("/signPDF"))
                .build()
                .directModelSubstitute(org.joda.time.LocalDate.class, java.sql.Date.class)
                .directModelSubstitute(org.joda.time.DateTime.class, java.util.Date.class)
                .apiInfo(apiInfo());
    }

}
