package net.jdesive.secy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@SpringBootApplication
public class SecyApplication {
	public static void main(String[] args) {
		SpringApplication.run(SecyApplication.class, args);
	}
}
