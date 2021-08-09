package com.sesame.securitycompoment;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurityComponentApplication {
	static String logoName=" _____  _____  _____   ___  ___  ___ _____                      \n" +
			"/  ___||  ___|/  ___| / _ \\ |  \\/  ||  ___|                     \n" +
			"\\ `--. | |__  \\ `--. / /_\\ \\| .  . || |__                       \n" +
			" `--. \\|  __|  `--. \\|  _  || |\\/| ||  __|                      \n" +
			"/\\__/ /| |___ /\\__/ /| | | || |  | || |___                      \n" +
			"\\____/ \\____/ \\____/ \\_| |_/\\_|  |_/\\____/                      \n" +
			"                                                                \n" +
			"                                                                \n" +
			" _____  _____  _____  _   _ ______  _____  _____ __   __        \n" +
			"/  ___||  ___|/  __ \\| | | || ___ \\|_   _||_   _|\\ \\ / /        \n" +
			"\\ `--. | |__  | /  \\/| | | || |_/ /  | |    | |   \\ V /         \n" +
			" `--. \\|  __| | |    | | | ||    /   | |    | |    \\ /          \n" +
			"/\\__/ /| |___ | \\__/\\| |_| || |\\ \\  _| |_   | |    | |          \n" +
			"\\____/ \\____/  \\____/ \\___/ \\_| \\_| \\___/   \\_/    \\_/          \n" +
			"                                                                \n" +
			"                                                                \n" +
			" _____  _____ ___  _________  _____  _   _  _____  _   _  _____ \n" +
			"/  __ \\|  _  ||  \\/  || ___ \\|  _  || \\ | ||  ___|| \\ | ||_   _|\n" +
			"| /  \\/| | | || .  . || |_/ /| | | ||  \\| || |__  |  \\| |  | |  \n" +
			"| |    | | | || |\\/| ||  __/ | | | || . ` ||  __| | . ` |  | |  \n" +
			"| \\__/ \\ \\_/ /| |  | || |    \\ \\_/ /| |\\  || |___ | |\\  |  | |  \n" +
			" \\____/ \\___/ \\_|  |_/\\_|     \\___/ \\_| \\_/\\____/ \\_| \\_/  \\_/  \n" +
			"                                                                \n" +
			"                                                                ";

	public static void main(String[] args) {
		SpringApplication.run(SecurityComponentApplication.class, args);
		System.out.println(logoName);

	}

}
