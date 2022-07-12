package com.sesame.securitycompoment;

import capec.model.AttackPattern;
import capec.model.Capec;
import capec.model.RelatedAttackPattern;
import capec.model.RelatedWeakness;
import graph.model.Edge;
import graph.model.Graph;
import graph.model.Node;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import rvd.model.RvdVulnerability;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.stream.Collectors;

import static com.sesame.securitycompoment.SecurityComponentApplication.*;

@Controller
public class GreetingController {
	ArrayList<Node> nodes = new ArrayList<>();
	ArrayList<Edge> edges = new ArrayList<>();

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
		node.setId(6);
		node.setLabel("ManosManos");
		model.addAttribute("node", node);
		model.addAttribute("nodes", nodes);
		model.addAttribute("edges", edges);
		return "attackgraph2";
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

		// search all rvdVulnerabilities to find related list of cwe for the cve provided
		ArrayList<String> cweFilteredArrayList = new ArrayList<>();
		for (int i = 0; i <rvdVulnerabilities.size() ; i++) {

			if (rvdVulnerabilities.get(i).cve.equals(cveId)){
				cweFilteredArrayList.add(rvdVulnerabilities.get(i).cwe);

			}
		}

		//Iterate all cwe from previous result to find the capecs
		for (int i = 0; i < cweFilteredArrayList.size(); i++) {
			String tempCWE=cweFilteredArrayList.get(i).substring(4);//remove the first 4 charactes eg: "CWE-115" becomes "115"
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

		/*// print the identified attacks
		System.out.println("The following CAPECs have been identified as potential attacks related to :" + cveId);
		for (int i = 0; i < capecsIdentified.size(); i++) {
			System.out.print(" "+capecsIdentified.get(i).iD);

		}*/


		//dummy test
		for (int i = 0; i <capecs.size() ; i++) {
			if(capecs.get(i).iD.equals("643")){
				test(capecs.get(i));
				break;
			}

		}


		//System.out.println(capecs.attack_Pattern.get(0).related_Weaknesses.related_Weakness);
		return "rvdresult";
	}

	public void test(AttackPattern attackPattern) {

		// create the root node in the Nodes arraylist
		Node rootNode = new Node();
		rootNode.setId(1);
		rootNode.setLabel(attackPattern.iD);
		rootNode.setShape("box");
		rootNode.setColor("#f7e39c");
		nodes.add(rootNode);

		int currentIndex = -1;
		while (nodes.size()>currentIndex+1) {
			currentIndex++;
			Node tempRootNode = new Node();
			tempRootNode=nodes.get(currentIndex);

			// find the Attack Pattern instance (from the identified attack patterns)
			// that corresponds to the nodes.get(currentIndex)
			AttackPattern currentAttackPattern = new AttackPattern();
			/*for (int i = 0; i < capecsIdentified.size(); i++) {
				if (capecsIdentified.get(i).iD.equals(nodes.get(currentIndex).getLabel())) {
					currentAttackPattern = capecsIdentified.get(i);
				}
			}*/
			for (int i = 0; i < capecs.size(); i++) {
				if (capecs.get(i).iD.equals(nodes.get(currentIndex).getLabel())) {
					currentAttackPattern = capecs.get(i);
				}
			}

			// for every canPrecede related attack pattern create a Node instance and an Edge instance
			// at the corresponding arraylists
			try{
				for (int i = 0; i < currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.size(); i++) {
					if (currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.get(i).nature.equals("CanPrecede")) {
						Node node = new Node();
						node.setId(nodes.size()+1);
						node.setLabel(currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.get(i).cAPECID);
						node.setShape("box");
						node.setColor("#f7e39c");
						nodes.add(node);

						Edge edge = new Edge();
						edge.setFrom(tempRootNode.getId());
						edge.setTo(node.getId());
						edge.setWidth(3);
						edges.add(edge);
					}
				}
			}
			catch (NullPointerException e){
				System.out.println(e.getMessage());
			}
		}

		// print the Nodes adn Edges that have been created
		for (int i = 0; i <nodes.size() ; i++) {
			System.out.println("Nodes "+nodes.get(i).getId());
		}
		for (int i = 0; i <edges.size() ; i++) {
			System.out.println("From " + edges.get(i).getFrom() + " to " + edges.get(i).getTo());
		}
	}

}
