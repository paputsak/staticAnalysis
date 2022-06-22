package com.sesame.securitycompoment;

import capec.model.Capec;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import rvd.model.RvdVulnerability;
import static com.sesame.securitycompoment.SecurityComponentApplication.rvdVulnerabilities;
import static com.sesame.securitycompoment.SecurityComponentApplication.capecs;
import java.util.ArrayList;



@Controller
public class GreetingController {

	@GetMapping("/greeting")
	public String greetingForm(Model model) {
		model.addAttribute("greeting", new Greeting());
		return "greeting";
	}

	@GetMapping("/attackgraph")
	public String attackgraph(Model model) {
		model.addAttribute("attackgraph");
		return "attackgraph";
	}

	@PostMapping("/greeting")
	public String greetingSubmit(@ModelAttribute Greeting greeting, Model model) {
		model.addAttribute("greeting", greeting);
		return "result";
	}

	@PostMapping("/rvdinsert")
	public String rvdInsert(@RequestBody ArrayList<RvdVulnerability> rvdJson) {
		//Generate the rvd database (rvdVulnerabilities) with the input from the rvdjson array
		rvdVulnerabilities=rvdJson;

		System.out.println(rvdVulnerabilities.get(1));
		return "rvdresult";
	}

	@PostMapping(value = "/capecinsert")
	public String capecInsert(@RequestBody Capec capecJson) {
		//public String capecInsert(@RequestBody String capecXML) {
		//Generate the capec database (capecs) with the input from the capecXML array
		capecs=capecJson.attack_Pattern_Catalog.attack_Patterns;

		System.out.println(capecs.attack_Pattern.get(0).related_Weaknesses.related_Weakness);
		return "rvdresult";
	}

	@PostMapping(value = "/searchwithcve")
	public String searchWithCve(@RequestBody String cveId) {
		//public String capecInsert(@RequestBody String capecXML) {
		//Generate the capec database (capecs) with the input from the capecXML array
		//1) search all rvdvulnerabilities to find related list of cwe for the cve provided
		//2) search capec based on the list of cwes to find the related list with capec ids
		//capecs=cveId.attack_Pattern_Catalog.attack_Patterns;

		//System.out.println(capecs.attack_Pattern.get(0).related_Weaknesses.related_Weakness);
		return "rvdresult";
	}

}
