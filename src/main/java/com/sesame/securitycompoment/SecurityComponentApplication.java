package com.sesame.securitycompoment;

import canprecede.model.CanPrecedeNode2;
import canprecede.model.CanPrecedeTree;
import canprecede.model.CanPrecedeTree2;
import capec.model.AttackPattern;
import capec.model.AttackPatterns;
import capec.model.Capec;
import capecextractor.Cve;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import graph.model.Graph;
import ode.CommonAttack;
import ode.CommonVulnerability;
/*import org.dom4j.DocumentHelper;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;*/
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import rvd.model.RvdVulnerability;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;

//import com.fasterxml.jackson.dataformat.xml.*;

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
	// all the vulnerabilities of the RVD repository
	public static ArrayList<RvdVulnerability> rvdVulnerabilities;

	// all the Attack Patterns of the CAPEC repository
	public static ArrayList<AttackPattern> capecs;

	// all the ODE Common Attacks
	public static ArrayList<CommonAttack> commonAttacks = new ArrayList<>();

	// all the ODE Common Vulnerabilities
	public static ArrayList<CommonVulnerability> commonVulnerabilities = new ArrayList<>();


	// all the trees created based on the canPrecede relationship among Attack Patterns
	public static ArrayList<CanPrecedeTree> canPrecedeTrees;

	// all the identified Attack Patterns for a given CVE-ID
	public static ArrayList<AttackPattern> capecsIdentified = new ArrayList<>();

	// a list with all available Template attack trees
	public static CanPrecedeTree2 allTemplateAttackTrees = new CanPrecedeTree2();

	// a list with all Template attack trees, matching to a given set of CAPECs
	public static CanPrecedeTree2 allMatchingTemplateAttackTrees = new CanPrecedeTree2();

	// this is the array of graphs (=attack trees) created due to the
	// canPrecede relationship among Attack Patterns
	public static CanPrecedeTree2 canPrecedeGraphs = new CanPrecedeTree2();

	// this is the array of graphs (=attack trees) created due to the
	// canFollow relationship among Attack Patterns
	public static ArrayList<Graph> canFollowGraphs;

	public static void main(String[] args) {
		SpringApplication.run(SecurityComponentApplication.class, args);
		System.out.println(logoName);

	}
}
