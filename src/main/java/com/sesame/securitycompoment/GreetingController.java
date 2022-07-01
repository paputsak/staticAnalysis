package com.sesame.securitycompoment;

import capec.model.AttackPattern;
import capec.model.Capec;
import capec.model.RelatedWeakness;
import graph.model.Node;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import rvd.model.RvdVulnerability;
import static com.sesame.securitycompoment.SecurityComponentApplication.rvdVulnerabilities;
import static com.sesame.securitycompoment.SecurityComponentApplication.capecs;
import java.util.ArrayList;

@Controller
public class GreetingController {

	/*@GetMapping("/greeting")
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
	}*/


	/*@GetMapping("/greeting")
	public String greeting(@RequestParam(name="name", required=false, defaultValue="World") Greeting greeting, Model model) {
		model.addAttribute("greeting", greeting);
		return "result";
	}*/

	@PostMapping("/greeting")
	public String greetingSubmit(@ModelAttribute Greeting greeting, Model model) {
		model.addAttribute("greeting", greeting);
		return "result";
	}


	@GetMapping("/attackgraph")
	public String attackgraph(Model model) {
		Node node = new Node();
		node.setId("6");
		node.setLabel("ManosManos");
		model.addAttribute("node", node);
		return "attackgraph";
	}




	///////////////////////////////////////////////////////////////////////////////////////
	@PostMapping("/rvdinsert")
	public String rvdInsert(@RequestBody ArrayList<RvdVulnerability> rvdJson) {
		//Generate the rvd database (rvdVulnerabilities) with the input from the rvdjson array
		rvdVulnerabilities=rvdJson;

		System.out.println("Local RVD Repository has been updated");
		return "rvdresult";
	}

	@PostMapping(value = "/capecinsert")
	public String capecInsert(@RequestBody Capec capecJson) {
		//public String capecInsert(@RequestBody String capecXML) {
		//Generate the capec database (capecs) with the input from the capecXML array
		capecs=capecJson.attack_Pattern_Catalog.attack_Patterns.attack_Pattern;

		System.out.println("Local CAPEC repository has been updated");
		return "rvdresult";
	}

	@PostMapping(value = "/searchwithcve")
	public String searchWithCve(@RequestBody String cveId) {
		//1) search all rvdvulnerabilities to find related list of cwe for the cve provided
		//2) search capec based on the list of cwes to find the related list with capec ids
		//capecs=cveId.attack_Pattern_Catalog.attack_Patterns;

		ArrayList<String> cweFilteredArrayList = new ArrayList<>();
		for (int i = 0; i <rvdVulnerabilities.size() ; i++) {

			if (rvdVulnerabilities.get(i).cve.equals(cveId)){
				cweFilteredArrayList.add(rvdVulnerabilities.get(i).cwe);

			}
		}
		ArrayList<AttackPattern> capecsIdentified = new ArrayList<>();
		//Iterate all cwe from previous result to find the capecs
		for (int i = 0; i < cweFilteredArrayList.size(); i++) {
			String tempCWE=cweFilteredArrayList.get(i).substring(4);//remove the first 4 charactes eg: "CWE-115" becomes "115"
			//String tempCWE=cweFilteredArrayList.get(i);


			for (int j = 0; j <capecs.size() ; j++) {
				AttackPattern tempCapec = capecs.get(j);
				for (int k = 0; k <tempCapec.related_Weaknesses.related_Weakness.size() ; k++) {
					RelatedWeakness tempRelatedWeakness=tempCapec.related_Weaknesses.related_Weakness.get(k);
					if (tempRelatedWeakness.cWEID.equals(tempCWE)){
						capecsIdentified.add(tempCapec);

					}
				}
			}
		}
		System.out.println("The following CAPECs have been identified as potential attacks related to :" + cveId);
		for (int i = 0; i < capecsIdentified.size(); i++) {
			System.out.print(" "+capecsIdentified.get(i).iD);

		}
		//System.out.println(capecs.attack_Pattern.get(0).related_Weaknesses.related_Weakness);
		return "rvdresult";
	}

	public String generateAttachGraphFromCAPEC(AttackPattern rootCapec){
		//search if the CAPEC in the canfollow field exist in the identifiedCapec. If it exists then update the nodes and edges
		for (int i = 0; i <rootCapec.related_Attack_Patterns.related_Attack_Pattern.size() ; i++) {
			if(rootCapec.related_Attack_Patterns.related_Attack_Pattern.get(i).nature.equals("CanPrecede")){
				//add the capec id to the nodes and update the edges accordingly
			}
		}

		return "attackgraph";
	}

}
