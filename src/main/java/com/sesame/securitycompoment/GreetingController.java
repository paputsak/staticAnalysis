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

import static com.sesame.securitycompoment.SecurityComponentApplication.*;

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
		//ArrayList<AttackPattern> capecsIdentified = new ArrayList<>();
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


	public void test(AttackPattern attackPattern) {
		ArrayList<Node> nodes = new ArrayList<>();
		ArrayList<Edge> edges = new ArrayList<>();

		Node rootNode = new Node();
		rootNode.setId(attackPattern.iD);
		rootNode.setLabel(attackPattern.iD);
		rootNode.setShape("box");
		rootNode.setColor("red");
		nodes.add(rootNode);

		int currentIndex = 0;
		int remainingIndex = 0;

		while (remainingIndex>0 && nodes.size()>currentIndex+1) {

			// move to the next item of nodes table
			// nodes.get(currentIndex);

			// find the Attack Pattern instance (from the identified attack patterns)
			// that corresponds to the nodes.get(currentIndex)
			AttackPattern currentAttackPattern = new AttackPattern();
			for (int i = 0; i < capecsIdentified.size(); i++) {
				if (capecsIdentified.get(i).iD.equals(nodes.get(currentIndex).getLabel())) {
					currentAttackPattern = capecsIdentified.get(i);
				}
			}

			for (int i = 0; i < currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.size(); i++) {
				if (currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.get(i).equals("CanPrecede")) {
					Node node = new Node();
					node.setId(currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.get(i).cAPECID);
					node.setLabel(currentAttackPattern.related_Attack_Patterns.related_Attack_Pattern.get(i).cAPECID);
					node.setShape("box");
					node.setColor("red");
					nodes.add(node);
					remainingIndex++;

					Edge edge = new Edge();
					edge.setFrom(Integer.parseInt(rootNode.getId()));
					edge.setTo(Integer.parseInt(node.getId()));
					edge.setWidth(3);
					edges.add(edge);
				}
			}
			remainingIndex--;
			currentIndex++;
		}
	}


	public String generateCanFollowAttachGraph(AttackPattern attackPattern) {

		// create the canFollowGraph
		Graph canFollowGraph = new Graph();
		ArrayList<Node> nodes = new ArrayList<>();
		canFollowGraph.setNodes(nodes);
		ArrayList<Edge> edges = new ArrayList<>();
		canFollowGraph.setEdges(edges);

		// create the root node of the graph
		Node rootNode = new Node();
		rootNode.setId("-1");
		rootNode.setLabel(attackPattern.iD);
		rootNode.setShape("box");
		rootNode.setColor("red");
		canFollowGraph.getNodes().add(rootNode);

		// add nodes and edges based on the "CanPrecede" relationship of the corresponding Attack Patterns
		int numberOfAddedNodes = 0;
		String response = addNodeEdgeToAttachGraph(canFollowGraph);
		while (response.contains("Node")) {
			response = addNodeEdgeToAttachGraph(canFollowGraph);
			numberOfAddedNodes++;
		}

		return numberOfAddedNodes + " Nodes were added to the canFollowGraph";
	}

	// this method adds a new node to the last node of a given canFollowGraph
	// based on the "CanPrecede" relationship of the corresponding Attack Patterns
	public String addNodeEdgeToAttachGraph(Graph canFollowGraph){

		// this is the method response
		String methodResponse = "";

		// find the last node in the graph
		Node startNode = canFollowGraph.getNodes().get(canFollowGraph.getNodes().size());

		// find the Attack Pattern instance (from the identified attack patterns)
		// that corresponds to the startNode.label
		AttackPattern startAttackPattern = new AttackPattern();
		for (int i = 0; i < capecsIdentified.size(); i++) {
			if (capecsIdentified.get(i).iD.equals(startNode.getLabel())) {
				startAttackPattern = capecsIdentified.get(i);
			}
		}

		// find if this Attack Pattern has a "CanPrecede" relationship with another one.
		ArrayList<RelatedAttackPattern> relatedAttackPatterns = startAttackPattern.related_Attack_Patterns.related_Attack_Pattern;
		for (int i = 0; i <relatedAttackPatterns.size() ; i++) {
			if(relatedAttackPatterns.get(i).nature.equals("CanPrecede")){
				// create the corresponding node to be added in the canFollowGraph graph
				Node node = new Node();
				node.setId(String.valueOf(i));
				node.setLabel(relatedAttackPatterns.get(i).cAPECID);
				node.setShape("box");
				node.setColor("#f7e39c");
				canFollowGraph.getNodes().add(node);

				// create the corresponding edge to be added in the canFollowGraph graph
				Edge edge = new Edge();
				edge.setFrom(Integer.parseInt(startNode.getId()));
				edge.setTo(i);
				edge.setWidth(3);
				canFollowGraph.getEdges().add(edge);

				// create the response
				methodResponse = methodResponse.concat("Node " + relatedAttackPatterns.get(i).cAPECID + " and an Edge from " + Integer.parseInt(startNode.getId()) + " to " + i + " have been created. ");
			}
		}
		return methodResponse;
	}

}
