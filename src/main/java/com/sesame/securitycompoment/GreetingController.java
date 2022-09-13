package com.sesame.securitycompoment;

import canprecede.model.CanPrecedeNode;
import canprecede.model.CanPrecedeNode2;
import canprecede.model.CanPrecedeTree;
import canprecede.model.CanPrecedeTree2;
import capec.model.AttackPattern;
import capec.model.Capec;
import capec.model.RelatedAttackPattern;
import capec.model.RelatedWeakness;
import graph.model.Edge;
import graph.model.Graph;
import graph.model.Node;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import rvd.model.RvdVulnerability;
import xml.model.report;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.stream.Collectors;

import static com.sesame.securitycompoment.SecurityComponentApplication.*;
import static org.springframework.http.MediaType.APPLICATION_XML;

@Controller
public class GreetingController {
	ArrayList<Node> nodes = new ArrayList<>();
	ArrayList<Edge> edges = new ArrayList<>();

	// create dummy TemplateTree
	String str = createRobotCrashesWithPersonTemplateAttackTree();
	String str2 = createRobotCrashesWithPersonTemplateAttackTree2();

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

		/*Node node = new Node();
		node.setId(9);
		node.setLabel("ManosManos");
		model.addAttribute("node", node)*/;
		model.addAttribute("nodes", nodes);
		model.addAttribute("edges", edges);
		model.addAttribute("trees", canPrecedeGraphs.getNodes());
		return "attackgraph2";
	}



	///////////////////////////////////////////////////////////////////////////////////////

	// API for inserting all RVD vulnerabilities into the local repo
	@PostMapping("/rvdinsert")
	public String rvdInsert(@RequestBody ArrayList<RvdVulnerability> rvdJson) {
		//Generate the rvd database (rvdVulnerabilities) with the input from the rvdjson array
		rvdVulnerabilities=rvdJson;

		System.out.println("Local RVD Repository has been updated. " + rvdVulnerabilities.size() + " vulnerabilities have been stored.");
		return "rvdresult";
	}

	// API for:
	// - inserting all CAPECs into the local repo
	// - creating the canPrecede attack trees
	@PostMapping(value = "/capecinsert")
	public String capecInsert(@RequestBody Capec capecJson) {
		//public String capecInsert(@RequestBody String capecXML) {
		//Generate the capec database (capecs) with the input from the capecXML array
		capecs=capecJson.attack_Pattern_Catalog.attack_Patterns.attack_Pattern;
		System.out.println("Local CAPEC Repository has been updated. " + capecs.size() + " known attacks have been stored.");

		// create the canPrecede trees
		//canPrecedeTrees = createCanPrecedeTrees(createCanPrecedeNodes(createCanPrecedeLists()));

		/*// print only the tree with more than 1 node
		System.out.println("Tree: ");
		for (int i = 0; i < canPrecedeTrees.size(); i++) {
			if (canPrecedeTrees.get(i).getNodes().size()>1) {
				System.out.println(canPrecedeTrees.get(i));
			}
		}*/

		//createCanPrecedeNode2s2();

		return "rvdresult";
	}

	// ******************************** (start) methods to create the canPrecedeTrees2 ***********************************
	// creates a CanPrecedeNode2 for every CAPEC in the local repo.
	// parent is not filled. Only first layer of children is filled.
	public ArrayList<CanPrecedeNode2> createCanPrecedeNode2s() {
		ArrayList<CanPrecedeNode2> canPrecedeNode2s = new ArrayList<>();

		// for all CAPECs
		for (int i = 0; i < capecs.size(); i++) {
			AttackPattern currentCapec = capecs.get(i);

			// create a CanPrecedeNode2
			CanPrecedeNode2 canPrecedeNode2 = new CanPrecedeNode2();
			canPrecedeNode2.setData(currentCapec.iD);
			// todo insert the right type of node
			//canPrecedeNode2.setGate(false);

			// for every canPrecede CAPEC
			if (currentCapec.related_Attack_Patterns!=null) {
				for (int j = 0; j < currentCapec.related_Attack_Patterns.related_Attack_Pattern.size(); j++) {
					RelatedAttackPattern currentRelatedCapec = currentCapec.related_Attack_Patterns.related_Attack_Pattern.get(j);

					// if nature == canPrecede add a child to the CanPrecedeNode2
					if (currentRelatedCapec.nature.equals("CanPrecede")) {
						CanPrecedeNode2 canPrecedeNode22 = new CanPrecedeNode2();
						canPrecedeNode22.setData(currentRelatedCapec.cAPECID);
						canPrecedeNode2.setChild(canPrecedeNode22);
					}
				}
			}

			// add the node to the response list
			canPrecedeNode2s.add(canPrecedeNode2);
		}

		// print the response list
		for (int i = 0; i < canPrecedeNode2s.size(); i++) {
			System.out.println("canPrecedeNode2: " + canPrecedeNode2s.get(i).toString());
		}
		System.out.println(" ");

		return canPrecedeNode2s;
	}

	public ArrayList<CanPrecedeNode2> createCanPrecedeNode2s2() {
		ArrayList<CanPrecedeNode2> canPrecedeNode2s = new ArrayList<>();

		// for all CAPECs
		for (int i = 0; i < capecs.size(); i++) {
			AttackPattern currentCapec = capecs.get(i);

			// add the node to the response list
			canPrecedeNode2s.add(addChildrenNodes(currentCapec.iD));
		}

		// print the response list
		for (int i = 0; i < canPrecedeNode2s.size(); i++) {
			System.out.println("canPrecedeNode2: " + canPrecedeNode2s.get(i).toString());
		}
		System.out.println(" ");

		return canPrecedeNode2s;
	}

	public CanPrecedeNode2 addChildrenNodes(String capec) {

		// find the corresponding AttackPattern
		AttackPattern correspondingAttackPattern = new AttackPattern();
		for (int i = 0; i < capecs.size(); i++) {
			AttackPattern currentCapec = capecs.get(i);
			if (currentCapec.iD.equals(capec)) {
				correspondingAttackPattern = currentCapec;
			}
		}

		// create a CanPrecedeNode2
		CanPrecedeNode2 canPrecedeNode2 = new CanPrecedeNode2();
		canPrecedeNode2.setData(correspondingAttackPattern.iD);
		// todo insert the right type of node
		//canPrecedeNode2.setGate(false);

		if (correspondingAttackPattern.related_Attack_Patterns!=null) {
			for (int i = 0; i < correspondingAttackPattern.related_Attack_Patterns.related_Attack_Pattern.size(); i++) {
				RelatedAttackPattern currentRelatedCapec = correspondingAttackPattern.related_Attack_Patterns.related_Attack_Pattern.get(i);

				// if nature == canPrecede add a child to the CanPrecedeNode2
				if (currentRelatedCapec.nature.equals("CanPrecede")) {
					CanPrecedeNode2 canPrecedeNode22 = new CanPrecedeNode2();
					canPrecedeNode22.setData(currentRelatedCapec.cAPECID);
					// todo insert the right type of node
					//canPrecedeNode2.setGate(false);
					canPrecedeNode2.setChild(addChildrenNodes(currentRelatedCapec.cAPECID));
					//canPrecedeNode2.setChild(canPrecedeNode22);
				}
			}
			return canPrecedeNode2;
		} else {
			return canPrecedeNode2;
		}
	}
	// ******************************** (end) methods to create the canPrecedeTrees2 *************************************

	// ******************************** (start) methods to create the canPrecedeTrees *************************************
	// Creates lists of CAPEC IDs based on the canPrecede relationship
	public ArrayList<ArrayList<String>> createCanPrecedeLists () {

		ArrayList<ArrayList<String>> allCanPrecedeCapecs = new ArrayList<>();

		// for each CAPECs
		for (int i = 0; i < capecs.size(); i++) {
			AttackPattern currentCapec = capecs.get(i);

			// create the canPrecede list of CAPEC IDs
			ArrayList<String> canPrecedeCapecs = new ArrayList<>();
			canPrecedeCapecs.add(currentCapec.iD);

			// for each related_Attack_Pattern
			if (currentCapec.related_Attack_Patterns != null) {
				for (int j = 0; j < currentCapec.related_Attack_Patterns.related_Attack_Pattern.size(); j++) {
					RelatedAttackPattern currentRelatedAttackPattern = currentCapec.related_Attack_Patterns.related_Attack_Pattern.get(j);

					// if -Nature == CanPrecede
					if (currentRelatedAttackPattern.nature.equals("CanPrecede")) {
						canPrecedeCapecs.add(currentRelatedAttackPattern.cAPECID);
					}
				}

				/*// print canPrecedeCapecs
				for (int j = 0; j < canPrecedeCapecs.size(); j++) {
					System.out.println("CAPEC ID: " + canPrecedeCapecs.get(j));
				}
				System.out.println(" ");*/
			}

			// add the created canPrecede list of CAPEC IDs to the overall list
			allCanPrecedeCapecs.add(canPrecedeCapecs);
		}
		return allCanPrecedeCapecs;
	}

	// Creates nodes using the output of the createCanPrecedeLists method as input
	public ArrayList<CanPrecedeNode> createCanPrecedeNodes (ArrayList<ArrayList<String>> allCanPrecedeCapecs) {
		ArrayList<CanPrecedeNode> allCanPrecedeNodes = new ArrayList<>();

		// for every canPrecede list
		for (int i = 0; i < allCanPrecedeCapecs.size(); i++) {
			ArrayList<String> currentCanPrecedeList = allCanPrecedeCapecs.get(i);

			// create the node for the first CAPEC of the list
			CanPrecedeNode canPrecedeNode = new CanPrecedeNode();
			canPrecedeNode.setData(currentCanPrecedeList.get(0));

			// for every CAPEC ID in the canPrecede list
			for (int j = 1; j < currentCanPrecedeList.size(); j++) {
				String currentCapecId = currentCanPrecedeList.get(j);

				// create a new node
				CanPrecedeNode canPrecedeNode2 = new CanPrecedeNode();
				ArrayList<String> children2 = new ArrayList<>();
				canPrecedeNode2.setChildren(children2);
				// set the node data
				canPrecedeNode2.setData(currentCapecId);
				// set the node parent
				canPrecedeNode2.setParent(currentCanPrecedeList.get(0));
				// add the current CAPEC to the children list of the first node
				canPrecedeNode.setChild(currentCapecId);


				allCanPrecedeNodes.add(canPrecedeNode2);
			}
			allCanPrecedeNodes.add(canPrecedeNode);
		}

		/*// print the list
		for (int i = 0; i < allCanPrecedeNodes.size(); i++) {
			System.out.println("canPrecedeNode: " + allCanPrecedeNodes.get(i));
		}
		System.out.println(" ");*/

		return allCanPrecedeNodes;
	}

	// Creates canPrecedeTrees using the output of the createCanPrecedeNodes method as input
	public ArrayList<CanPrecedeTree> createCanPrecedeTrees (ArrayList<CanPrecedeNode> allCanPrecedeNodes) {
		ArrayList<CanPrecedeTree> allCanPrecedeTrees = new ArrayList<>();

		// create the root list
		ArrayList<CanPrecedeNode> canPrecedeRootNodes = new ArrayList<>();
		for (int i = 0; i < allCanPrecedeNodes.size(); i++) {
			CanPrecedeNode currentCanPrecedeNode = allCanPrecedeNodes.get(i);

			// check all the other nodes
			boolean isRootFlag = true;
			for (int j = 0; j < allCanPrecedeNodes.size(); j++) {
				CanPrecedeNode currentCanPrecedeNode2 = allCanPrecedeNodes.get(j);
				for (int k = 0; k < currentCanPrecedeNode2.getChildren().size(); k++) {
					if (currentCanPrecedeNode.getData().equals(currentCanPrecedeNode2.getChildren().get(k))) {
						isRootFlag = false;
					}
				}
			}
			if (isRootFlag) {
				canPrecedeRootNodes.add(currentCanPrecedeNode);
			}
		}

		/*//print canPrecedeRootNodes list
		for (int i = 0; i < canPrecedeRootNodes.size(); i++) {
			System.out.println("canPrecedeRootNode: " + canPrecedeRootNodes.get(i));
		}
		System.out.println(" ");*/

		// create the canPrecede trees based on the canPrecedeRootNodes list
		for (int i = 0; i < canPrecedeRootNodes.size(); i++) {
			CanPrecedeNode currentCanPrecedeRootNode =  canPrecedeRootNodes.get(i);

			ArrayList<CanPrecedeNode> stack = new ArrayList<>();

			// create the canPrecede tree
			CanPrecedeTree canPrecedeTree = new CanPrecedeTree();
			canPrecedeTree.setNode(currentCanPrecedeRootNode);

			// add an OR gate if there are children
			if (currentCanPrecedeRootNode.getChildren().size()>0) {
				CanPrecedeNode canPrecedeNodeGate = new CanPrecedeNode();
				canPrecedeNodeGate.setGate(true);
				canPrecedeNodeGate.setGateType("OR");
				stack.add(canPrecedeNodeGate);
			}
			// put children of currentCanPrecedeRootNode in the stack
			for (int j = 0; j < currentCanPrecedeRootNode.getChildren().size(); j++) {
				CanPrecedeNode canPrecedeNode = getCanPrecedeNode(allCanPrecedeNodes, currentCanPrecedeRootNode.getChildren().get(j));
				if (canPrecedeNode!=null) {
					stack.add(canPrecedeNode);
				}
			}

			// add all the nodes in the corresponding tree
			while (stack.size()!=0) {
				canPrecedeTree.setNode(stack.get(0));

				// add an OR gate if there are children
				if (stack.get(0).getChildren().size()>0) {
					CanPrecedeNode canPrecedeNodeGate = new CanPrecedeNode();
					canPrecedeNodeGate.setGate(true);
					canPrecedeNodeGate.setGateType("OR");
					stack.add(canPrecedeNodeGate);
				}

				// add every child of stack.get(0) to the stack
				for (int j = 0; j < stack.get(0).getChildren().size(); j++) {
					stack.add(getCanPrecedeNode(allCanPrecedeNodes, stack.get(0).getChildren().get(j)));
				}

				stack.remove(0);
			}

			// add the tree to the allCanPrecedeTrees list
			allCanPrecedeTrees.add(canPrecedeTree);

			// print the tree
			//System.out.println("Tree: " + canPrecedeTree);
		}

		return allCanPrecedeTrees;
	}

	// Returns a canPrecedeNode, or null if the node does not exist
	public CanPrecedeNode getCanPrecedeNode (ArrayList<CanPrecedeNode> allCanPrecedeNodes, String node) {
		CanPrecedeNode canPrecedeNode = null;
		for (int k = 0; k < allCanPrecedeNodes.size(); k++) {
			if (allCanPrecedeNodes.get(k).getData().equals(node)) {
				canPrecedeNode = allCanPrecedeNodes.get(k);
			}
		}
		return canPrecedeNode;
	}
	// ******************************** (end) methods to create the canPrecede trees *************************************

	// API for identifying a list of CAPECs based on a given list of CPEs
	@PostMapping(value = "/searchwithcpes")
	public String searchWithCpes(@RequestBody ArrayList<String> cpes) {

		// This list stores all the identified potential known attacks
		//ArrayList<AttackPattern> capecsIdentified = new ArrayList<>();

		// do for every incoming CPE
		for (String currentCpe : cpes) {
			// get every separate word from the CPE
			String[] currentCpeArr = currentCpe.split(" ");
			String[] commonWords = {"server", "Components", "FTP"};
			ArrayList<String> currentCpeArrList = new ArrayList<>();
			Collections.addAll(currentCpeArrList, currentCpeArr);
			ArrayList<String> commonWordsArrList = new ArrayList<>();
			Collections.addAll(commonWordsArrList, commonWords);

			// remove the common words from the CPE words
			currentCpeArrList.removeAll(commonWordsArrList);

			// Put in the "cweFilteredArrayList" the CWEs that are related
			// to each of the CPEs, searching the RVD Vulnerabilities
			ArrayList<String> cweFilteredArrayList = new ArrayList<>();
			// for every separate word of the CPE
			for (String value : currentCpeArrList) {
				//System.out.println("current CPE: " + value);

				// for every RVD vulnerability
				for (RvdVulnerability currentVuln : rvdVulnerabilities) {
					// check the title, description, system and vendor elements
					boolean titleFlag = false;
					if (currentVuln.title != null) {
						if (currentVuln.title.contains(value)) {
							titleFlag = true;
						}
					}
					boolean descriptionFlag = false;
					if (currentVuln.description != null) {
						if (currentVuln.description.contains(value)) {
							descriptionFlag = true;
						}
					}
					boolean systemFlag = false;
					if (currentVuln.system != null) {
						if (currentVuln.system.contains(value)) {
							systemFlag = true;
						}
					}
					boolean vendorFlag = false;
					if (currentVuln.vendor != null) {
						if (currentVuln.vendor.contains(value)) {
							vendorFlag = true;
						}
					}
					if (titleFlag || descriptionFlag || systemFlag || vendorFlag) {
						cweFilteredArrayList.add(currentVuln.cwe);
						//System.out.println("current CVE: " + currentVuln.cve);
					}
				}
			}

			/*// print the "cweFilteredArrayList"
			System.out.println(" ");
			System.out.println("cweFilteredArrayList: ");
			for (String s : cweFilteredArrayList) {
				System.out.println(s);
			}
			System.out.println(" ");*/

			// Put in the "capecsIdentified" list the CAPECs that are related
			// to each of the CWEs identified above, searching the CAPEC repo
			for (String s : cweFilteredArrayList) {
				//remove the first 4 charactes eg: "CWE-115" becomes "115"
				String tempCWE = s.substring(4);
				for (AttackPattern tempCapec : capecs) {
					if (tempCapec.related_Weaknesses != null) {
						for (int l = 0; l < tempCapec.related_Weaknesses.related_Weakness.size(); l++) {
							RelatedWeakness tempRelatedWeakness = tempCapec.related_Weaknesses.related_Weakness.get(l);
							if (tempRelatedWeakness.cWEID.equals(tempCWE)) {
								capecsIdentified.add(tempCapec);
							}
						}
					}
				}
			}
		}

		// print the list with the identified CAPECs
		System.out.println(" ");
		System.out.println("The following CAPECs have been identified as potential attacks related to list of incoming CVE-IDs:");
		if (capecsIdentified.size()>0) {
			for (AttackPattern attackPattern : capecsIdentified) {
				System.out.print(" " + attackPattern.iD);
			}
		}
		System.out.println(" ");
		System.out.println("capecsIdentified.size= " + capecsIdentified.size());
		System.out.println(" ");

		// select the Template Attack Trees that match the CAPECs in the capecsIdentified list
		// and depict the matched Template attack trees
		visualizeAttackTrees(getMatchingTemplateTrees());

		return "rvdresult";
	}

	// fill capecsIdentified list with predefined CAPECs
	@PostMapping(value = "/fillCapecsIdentifiedList")
	public String fillCapecsIdentifiedList(@RequestBody ArrayList<String> capecIds) {

		// clean the list
		capecsIdentified.clear();

		// Put in the "capecsIdentified" list the CAPECs that are included in capecIds list
		for (String s : capecIds) {
			for (AttackPattern tempCapec : capecs) {
				if (tempCapec.iD.equals(s)) {
					capecsIdentified.add(tempCapec);
					break;
				}
			}
		}

		// print the list with the identified CAPECs
		System.out.println(" ");
		System.out.println("The following CAPECs have been identified as potential attacks related to list of incoming CVE-IDs:");
		if (capecsIdentified.size()>0) {
			for (AttackPattern attackPattern : capecsIdentified) {
				System.out.print(" " + attackPattern.iD);
			}
		}
		System.out.println(" ");
		System.out.println("The predefined capecsIdentified is created");
		System.out.println(" ");

		// select the Template Attack Trees that match the CAPECs in the capecsIdentified list
		// and depict the matched Template attack trees
		visualizeAttackTrees(getMatchingTemplateTrees());

		return "rvdresult";
	}


	// ************************************************ (start) Template Attack trees ************************************************

	// Creates a Template attack tree where the root attack is to cause a crash between a robot and a person
	@GetMapping("/templateTree")
	public String createRobotCrashesWithPersonTemplateAttackTree () {

		// create the nodes
		CanPrecedeNode2 capec85 = new CanPrecedeNode2();
		capec85.setId(11);
		capec85.setParentId(12);
		capec85.setData("CAPEC-85");
		capec85.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec63 = new CanPrecedeNode2();
		capec63.setId(12);
		capec63.setParentId(14);
		capec63.setData("CAPEC-63");
		capec63.setNodeType(CanPrecedeNode2.Type.CAPEC);
		capec63.setChild(capec85);

		CanPrecedeNode2 capec8 = new CanPrecedeNode2();
		capec8.setId(13);
		capec8.setParentId(14);
		//capec8.setData("CAPEC-8: Buffer overflow in an API call.");
		capec8.setData("CAPEC-8");
		capec8.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 orGate = new CanPrecedeNode2();
		orGate.setId(14);
		orGate.setParentId(15);
		orGate.setData("OR");
		orGate.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate.setChild(capec8);
		orGate.setChild(capec63);

		CanPrecedeNode2 compromiseApi = new CanPrecedeNode2();
		compromiseApi.setId(15);
		compromiseApi.setParentId(16);
		compromiseApi.setData("Compromise the API of the robot.");
		compromiseApi.setNodeType(CanPrecedeNode2.Type.STATE);
		compromiseApi.setChild(orGate);

		/*CanPrecedeNode2 useRosCli = new CanPrecedeNode2();
		useRosCli.setData("The Attacker uses ROS CLI.");
		useRosCli.setGate(false);*/

		CanPrecedeNode2 orGate2 = new CanPrecedeNode2();
		orGate2.setId(16);
		orGate2.setParentId(17);
		orGate2.setData("OR");
		orGate2.setNodeType(CanPrecedeNode2.Type.GATE);
		//orGate2.setChild(useRosCli);
		orGate2.setChild(compromiseApi);

		CanPrecedeNode2 publishArbitraryData = new CanPrecedeNode2();
		publishArbitraryData.setId(17);
		publishArbitraryData.setParentId(18);
		publishArbitraryData.setData("The Attacker publishes arbitrary data to a topic.");
		publishArbitraryData.setNodeType(CanPrecedeNode2.Type.STATE);
		publishArbitraryData.setChild(orGate2);

		CanPrecedeNode2 robotCrashesWithPerson = new CanPrecedeNode2();
		robotCrashesWithPerson.setId(18);
		robotCrashesWithPerson.setData("The robot crashes with a person.");
		robotCrashesWithPerson.setNodeType(CanPrecedeNode2.Type.STATE);
		robotCrashesWithPerson.setChild(publishArbitraryData);

		// store the tree in a public variable
		allTemplateAttackTrees.setNode(robotCrashesWithPerson);

		// print the tree
		for (int i = 0; i < allTemplateAttackTrees.getNodes().size(); i++) {
			CanPrecedeNode2 currentTemplateTree = allTemplateAttackTrees.getNodes().get(i);
			System.out.println("TemplateAttackTree: " + currentTemplateTree);
		}
		System.out.println(" ");

		return "rvdresult";
	}

	// Creates a Template attack tree where the root attack is to cause a crash between a robot and a person
	// and different gates than the previous one.
	@GetMapping("/templateTree2")
	public String createRobotCrashesWithPersonTemplateAttackTree2 () {

		// create the nodes
		CanPrecedeNode2 capec9 = new CanPrecedeNode2();
		capec9.setId(22);
		capec9.setParentId(24);
		capec9.setData("CAPEC-9");
		capec9.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec8 = new CanPrecedeNode2();
		capec8.setId(23);
		capec8.setParentId(24);
		//capec8.setData("CAPEC-8: Buffer overflow in an API call.");
		capec8.setData("CAPEC-8");
		capec8.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 andGate = new CanPrecedeNode2();
		andGate.setId(24);
		andGate.setParentId(25);
		andGate.setData("AND");
		andGate.setNodeType(CanPrecedeNode2.Type.GATE);
		andGate.setChild(capec8);
		andGate.setChild(capec9);

		CanPrecedeNode2 compromiseApi = new CanPrecedeNode2();
		compromiseApi.setId(25);
		compromiseApi.setParentId(26);
		compromiseApi.setData("Compromise the API of the robot.");
		compromiseApi.setNodeType(CanPrecedeNode2.Type.STATE);
		compromiseApi.setChild(andGate);

		/*CanPrecedeNode2 useRosCli = new CanPrecedeNode2();
		useRosCli.setData("The Attacker uses ROS CLI.");
		useRosCli.setGate(false);*/

		CanPrecedeNode2 orGate2 = new CanPrecedeNode2();
		orGate2.setId(26);
		orGate2.setParentId(27);
		orGate2.setData("OR");
		orGate2.setNodeType(CanPrecedeNode2.Type.GATE);
		//orGate2.setChild(useRosCli);
		orGate2.setChild(compromiseApi);

		CanPrecedeNode2 publishArbitraryData = new CanPrecedeNode2();
		publishArbitraryData.setId(27);
		publishArbitraryData.setParentId(28);
		publishArbitraryData.setData("The Attacker publishes arbitrary data to a topic.");
		publishArbitraryData.setNodeType(CanPrecedeNode2.Type.STATE);
		publishArbitraryData.setChild(orGate2);

		CanPrecedeNode2 robotCrashesWithPerson = new CanPrecedeNode2();
		robotCrashesWithPerson.setId(28);
		robotCrashesWithPerson.setData("The robot crashes with a person.");
		robotCrashesWithPerson.setNodeType(CanPrecedeNode2.Type.STATE);
		robotCrashesWithPerson.setChild(publishArbitraryData);

		// store the tree in a public variable
		allTemplateAttackTrees.setNode(robotCrashesWithPerson);

		// print the tree
		for (int i = 0; i < allTemplateAttackTrees.getNodes().size(); i++) {
			CanPrecedeNode2 currentTemplateTree = allTemplateAttackTrees.getNodes().get(i);
			System.out.println("TemplateAttackTree: " + currentTemplateTree);
		}
		System.out.println(" ");

		return "rvdresult";
	}

	// create a Template Attack tree for KIOS #1
	@GetMapping("/kiosΤemplateTree1")
	public String kiosTemplateAttackTree1 () {

		// create the nodes
		CanPrecedeNode2 capec75 = new CanPrecedeNode2();
		capec75.setId(101);
		capec75.setParentId(105);
		capec75.setData("CAPEC-75");
		capec75.setExtendedDescription("CAPEC-75: Manipulating Writeable Configuration Files.");
		capec75.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec46 = new CanPrecedeNode2();
		capec46.setId(102);
		capec46.setParentId(105);
		capec46.setData("CAPEC-46");
		capec46.setExtendedDescription("CAPEC-46: Overflow Variables and Tags.");
		capec46.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec35 = new CanPrecedeNode2();
		capec35.setId(103);
		capec35.setParentId(105);
		capec35.setData("CAPEC-35");
		capec35.setExtendedDescription("CAPEC-35: Leverage Executable Code in Non-Executable Files.");
		capec35.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec23 = new CanPrecedeNode2();
		capec23.setId(104);
		capec23.setParentId(105);
		capec23.setData("CAPEC-23");
		capec23.setExtendedDescription("CAPEC-23: File Content Injection.");
		capec23.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 orGate = new CanPrecedeNode2();
		orGate.setId(105);
		orGate.setParentId(106);
		orGate.setData("OR");
		orGate.setExtendedDescription("OR Gate");
		orGate.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate.setChild(capec75);
		orGate.setChild(capec46);
		orGate.setChild(capec35);
		orGate.setChild(capec23);

		CanPrecedeNode2 manipulateConfigFiles = new CanPrecedeNode2();
		manipulateConfigFiles.setId(106);
		manipulateConfigFiles.setParentId(108);
		manipulateConfigFiles.setData("Manipulate Configuration Files");
		manipulateConfigFiles.setExtendedDescription("If a configuration file is not properly protected by the system access control, an attacker can write configuration information to alter input/output through system logs, database connections, malicious URLs and so on.");
		manipulateConfigFiles.setNodeType(CanPrecedeNode2.Type.STATE);
		manipulateConfigFiles.setChild(orGate);

		CanPrecedeNode2 capec13 = new CanPrecedeNode2();
		capec13.setId(107);
		capec13.setParentId(108);
		capec13.setData("CAPEC-13");
		capec13.setExtendedDescription("CAPEC-13: Subverting Environment Variable Values.");
		capec13.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 orGate2 = new CanPrecedeNode2();
		orGate2.setId(108);
		orGate2.setParentId(109);
		orGate2.setData("OR");
		orGate2.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate2.setChild(manipulateConfigFiles);
		orGate2.setChild(capec13);

		CanPrecedeNode2 changeUrlStream = new CanPrecedeNode2();
		changeUrlStream.setId(109);
		changeUrlStream.setParentId(110);
		changeUrlStream.setData("Alter video stream URL");
		changeUrlStream.setExtendedDescription("The Attacker alters the URL of the video stream which serves as input to the Video Web Streamer.");
		changeUrlStream.setNodeType(CanPrecedeNode2.Type.STATE);
		changeUrlStream.setChild(orGate2);

		CanPrecedeNode2 consumeMaliciousSource = new CanPrecedeNode2();
		consumeMaliciousSource.setId(110);
		consumeMaliciousSource.setParentId(111);
		consumeMaliciousSource.setData("Malicious source consumption");
		consumeMaliciousSource.setExtendedDescription("Video Web Streamer consumes stream from the malicious source.");
		consumeMaliciousSource.setNodeType(CanPrecedeNode2.Type.STATE);
		consumeMaliciousSource.setChild(changeUrlStream);

		CanPrecedeNode2 wrongAssessment = new CanPrecedeNode2();
		wrongAssessment.setId(111);
		wrongAssessment.setParentId(112);
		wrongAssessment.setData("Mistaken assessment of the disaster scale");
		wrongAssessment.setExtendedDescription("Aerial view from the malicious source leads to mistaken assessment of the disaster scale.");
		wrongAssessment.setNodeType(CanPrecedeNode2.Type.STATE);
		wrongAssessment.setChild(consumeMaliciousSource);

		CanPrecedeNode2 insufficientOperationDesign = new CanPrecedeNode2();
		insufficientOperationDesign.setId(112);
		insufficientOperationDesign.setData("Insufficient design of mitigation actions");
		insufficientOperationDesign.setExtendedDescription("Mistaken assessment of the disaster scale leads to insufficient design of the mitigation actions.");
		insufficientOperationDesign.setNodeType(CanPrecedeNode2.Type.STATE);
		insufficientOperationDesign.setChild(wrongAssessment);

		// store the tree in a public variable
		allTemplateAttackTrees.setNode(insufficientOperationDesign);

		// print the tree
		for (int i = 0; i < allTemplateAttackTrees.getNodes().size(); i++) {
			CanPrecedeNode2 currentTemplateTree = allTemplateAttackTrees.getNodes().get(i);
			System.out.println("TemplateAttackTree: " + currentTemplateTree);
		}
		System.out.println(" ");

		return "rvdresult";
	}

	// create a Template Attack tree for KIOS #1
	@GetMapping("/kiosΤemplateTree2")
	public String kiosTemplateAttackTree2 () {

		// create the nodes
		CanPrecedeNode2 capec488 = new CanPrecedeNode2();
		capec488.setId(225);
		capec488.setParentId(212);
		capec488.setData("CAPEC-488");
		capec488.setExtendedDescription("CAPEC-488: HTTP Flood.");
		capec488.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec487 = new CanPrecedeNode2();
		capec487.setId(224);
		capec487.setParentId(212);
		capec487.setData("CAPEC-487");
		capec487.setExtendedDescription("CAPEC-487: ICMP Flood.");
		capec487.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec486 = new CanPrecedeNode2();
		capec486.setId(223);
		capec486.setParentId(212);
		capec486.setData("CAPEC-486");
		capec486.setExtendedDescription("CAPEC-486: UDP Flood.");
		capec486.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec482 = new CanPrecedeNode2();
		capec482.setId(222);
		capec482.setParentId(212);
		capec482.setData("CAPEC-482");
		capec482.setExtendedDescription("CAPEC-482: TCP Flood.");
		capec482.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec628 = new CanPrecedeNode2();
		capec628.setId(221);
		capec628.setParentId(213);
		capec628.setData("CAPEC-628");
		capec628.setExtendedDescription("CAPEC-628: GPS Spoofing.");
		capec628.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec173 = new CanPrecedeNode2();
		capec173.setId(220);
		capec173.setParentId(213);
		capec173.setData("CAPEC-173");
		capec173.setExtendedDescription("CAPEC-173: Action Spoofing.");
		capec173.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec151 = new CanPrecedeNode2();
		capec151.setId(219);
		capec151.setParentId(213);
		capec151.setData("CAPEC-151");
		capec151.setExtendedDescription("CAPEC-151: Identity Spoofing.");
		capec151.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec148 = new CanPrecedeNode2();
		capec148.setId(218);
		capec148.setParentId(213);
		capec148.setData("CAPEC-148");
		capec148.setExtendedDescription("CAPEC-148: Content Spoofing.");
		capec148.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec67 = new CanPrecedeNode2();
		capec67.setId(217);
		capec67.setParentId(211);
		capec67.setData("CAPEC-67");
		capec67.setExtendedDescription("CAPEC-67: String Format Overflow in syslog().");
		capec67.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec8 = new CanPrecedeNode2();
		capec8.setId(216);
		capec8.setParentId(211);
		capec8.setData("CAPEC-8");
		capec8.setExtendedDescription("CAPEC-8: Buffer overflow in an API Call.");
		capec8.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec46 = new CanPrecedeNode2();
		capec46.setId(215);
		capec46.setParentId(211);
		capec46.setData("CAPEC-46");
		capec46.setExtendedDescription("CAPEC-46: Overflow Variables and Tags.");
		capec46.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 capec45 = new CanPrecedeNode2();
		capec45.setId(214);
		capec45.setParentId(211);
		capec45.setData("CAPEC-45");
		capec45.setExtendedDescription("CAPEC-45: Buffer Overflow via Symbolic Links.");
		capec45.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 orGate5 = new CanPrecedeNode2();
		orGate5.setId(213);
		orGate5.setParentId(210);
		orGate5.setData("OR");
		orGate5.setExtendedDescription("OR Gate");
		orGate5.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate5.setChild(capec148);
		orGate5.setChild(capec151);
		orGate5.setChild(capec173);
		orGate5.setChild(capec628);

		CanPrecedeNode2 orGate4 = new CanPrecedeNode2();
		orGate4.setId(212);
		orGate4.setParentId(209);
		orGate4.setData("OR");
		orGate4.setExtendedDescription("OR Gate");
		orGate4.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate4.setChild(capec482);
		orGate4.setChild(capec486);
		orGate4.setChild(capec487);
		orGate4.setChild(capec488);

		CanPrecedeNode2 orGate3 = new CanPrecedeNode2();
		orGate3.setId(211);
		orGate3.setParentId(208);
		orGate3.setData("OR");
		orGate3.setExtendedDescription("OR Gate");
		orGate3.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate3.setChild(capec8);
		orGate3.setChild(capec45);
		orGate3.setChild(capec46);

		CanPrecedeNode2 spoofing = new CanPrecedeNode2();
		spoofing.setId(210);
		spoofing.setParentId(207);
		spoofing.setData("Spoofing");
		spoofing.setExtendedDescription("Spoofing, as it pertains to cybersecurity, is when someone or something pretends to be something else in an attempt to gain our confidence, get access to our systems, steal data, steal money, or spread malware.");
		spoofing.setNodeType(CanPrecedeNode2.Type.STATE);
		spoofing.setChild(orGate5);

		CanPrecedeNode2 flooding = new CanPrecedeNode2();
		flooding.setId(209);
		flooding.setParentId(207);
		flooding.setData("Flooding");
		flooding.setExtendedDescription("The intruder sends a high number of connection requests to the target node until resources of the target node are completely wasted.");
		flooding.setNodeType(CanPrecedeNode2.Type.STATE);
		flooding.setChild(orGate4);

		CanPrecedeNode2 bufferOverflow = new CanPrecedeNode2();
		bufferOverflow.setId(208);
		bufferOverflow.setParentId(207);
		bufferOverflow.setData("Buffer overflow");
		bufferOverflow.setExtendedDescription("Buffer overflow occurs when the amount of data in the buffer exceeds its storage capacity.");
		bufferOverflow.setNodeType(CanPrecedeNode2.Type.STATE);
		bufferOverflow.setChild(orGate3);

		CanPrecedeNode2 orGate2 = new CanPrecedeNode2();
		orGate2.setId(207);
		orGate2.setParentId(203);
		orGate2.setData("OR");
		orGate2.setExtendedDescription("OR Gate");
		orGate2.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate2.setChild(bufferOverflow);
		orGate2.setChild(flooding);
		orGate2.setChild(spoofing);

		CanPrecedeNode2 capec604 = new CanPrecedeNode2();
		capec604.setId(206);
		capec604.setParentId(204);
		capec604.setData("CAPEC-604");
		capec604.setExtendedDescription("CAPEC-604: Wi-Fi Jamming.");
		capec604.setNodeType(CanPrecedeNode2.Type.CAPEC);

		CanPrecedeNode2 falsifyingCommands = new CanPrecedeNode2();
		falsifyingCommands.setId(205);
		falsifyingCommands.setParentId(202);
		falsifyingCommands.setData("Falsifying Commands");
		falsifyingCommands.setExtendedDescription("The Attacker alters the commands that GCS sends to the Drone.");
		falsifyingCommands.setNodeType(CanPrecedeNode2.Type.STATE);

		CanPrecedeNode2 jammingAttack = new CanPrecedeNode2();
		jammingAttack.setId(204);
		jammingAttack.setParentId(202);
		jammingAttack.setData("Jamming attack");
		jammingAttack.setExtendedDescription("The signal-to-noise ratio at the receiver side is decreases and the existing wireless communication is disrupted due to a Jamming attack.");
		jammingAttack.setNodeType(CanPrecedeNode2.Type.STATE);
		jammingAttack.setChild(capec604);

		CanPrecedeNode2 dosAttack = new CanPrecedeNode2();
		dosAttack.setId(203);
		dosAttack.setParentId(202);
		dosAttack.setData("DoS attack");
		dosAttack.setExtendedDescription("A Denial-of-service attack is conducted against the target Drone.");
		dosAttack.setNodeType(CanPrecedeNode2.Type.STATE);
		dosAttack.setChild(orGate2);

		CanPrecedeNode2 orGate = new CanPrecedeNode2();
		orGate.setId(202);
		orGate.setParentId(201);
		orGate.setData("OR");
		orGate.setExtendedDescription("OR Gate");
		orGate.setNodeType(CanPrecedeNode2.Type.GATE);
		orGate.setChild(dosAttack);
		orGate.setChild(jammingAttack);
		orGate.setChild(falsifyingCommands);

		CanPrecedeNode2 noDroneCommunication = new CanPrecedeNode2();
		noDroneCommunication.setId(201);
		noDroneCommunication.setData("Communication interruption with Drone");
		noDroneCommunication.setExtendedDescription("Communication with the target Drone is lost.");
		noDroneCommunication.setNodeType(CanPrecedeNode2.Type.STATE);
		noDroneCommunication.setChild(orGate);

		// store the tree in a public variable
		allTemplateAttackTrees.setNode(noDroneCommunication);

		// print the tree
		for (int i = 0; i < allTemplateAttackTrees.getNodes().size(); i++) {
			CanPrecedeNode2 currentTemplateTree = allTemplateAttackTrees.getNodes().get(i);
			System.out.println("TemplateAttackTree: " + currentTemplateTree);
		}
		System.out.println(" ");

		return "rvdresult";
	}

	// ************************************************ (end) Template Attack trees ************************************************


	// ******************************** (start) methods to select Template Attack trees ***********************************
	// returns all the matched template trees
	public CanPrecedeTree2 getMatchingTemplateTrees () {
		CanPrecedeTree2 matchingTrees = new CanPrecedeTree2();

		// check all the available template attack trees
		for (int i = 0; i < allTemplateAttackTrees.getNodes().size(); i++) {
			CanPrecedeNode2 currentTemplateTree = allTemplateAttackTrees.getNodes().get(i);
			if (checkLeavesFromCanPrecedeNode2(currentTemplateTree)) {
				matchingTrees.setNode(currentTemplateTree);
				System.out.println("Attack tree with root \"" + currentTemplateTree.getData() + "\" is a potential attack tree for the target system.");
			} else {
				System.out.println("Attack tree with root \"" + currentTemplateTree.getData() + "\" is NOT a potential attack tree for the target system.");
			}
		}

		canPrecedeGraphs = matchingTrees;
		return matchingTrees;
	}

	// checks if a given node (=tree) is a match or not based on the identified capecs
	public boolean checkLeavesFromCanPrecedeNode2(CanPrecedeNode2 node) {

		boolean matchFlag = true;
		// if the node has children
		if (node.getChildren().size() > 0) {

			// if the node is gate
			if (node.getNodeType().equals(CanPrecedeNode2.Type.GATE)) {
				// check if each child matches or not (childrenMatches list)
				ArrayList<Boolean> childrenMatches = new ArrayList<>();
				for (int i = 0; i < node.getChildren().size(); i++) {
					CanPrecedeNode2 currentChild = node.getChildren().get(i);
					childrenMatches.add(checkLeavesFromCanPrecedeNode2(currentChild));
				}
				// OR gate
				if (node.getData().equals("OR")) {
					matchFlag = false;
					for (int i = 0; i < childrenMatches.size(); i++) {
						if (childrenMatches.get(i).booleanValue() == true) {
							matchFlag = true;
							break;
						}
					}
				}
				// AND gate
				if (node.getData().equals("AND")) {
					matchFlag = true;
					for (int i = 0; i < childrenMatches.size(); i++) {
						if (childrenMatches.get(i).booleanValue() == false) {
							matchFlag = false;
							break;
						}
					}
				}
			}

			// if the node is not a gate
			if (!node.getNodeType().equals(CanPrecedeNode2.Type.GATE)) {
				matchFlag = checkLeavesFromCanPrecedeNode2(node.getChildren().get(0));
			}

/*			for (int i = 0; i < node.getChildren().size(); i++) {
				CanPrecedeNode2 currentChild = node.getChildren().get(i);
				if (checkLeavesFromCanPrecedeNode2(currentChild)==false) {
					match = false;
					break;
				}
			}*/
			return matchFlag;
		} else {
			matchFlag = checkCapec(node.getData());
			return matchFlag;
		}
	}

	// checks if a given CAPEC belongs in the capecsIdentified list
	public boolean checkCapec (String capec) {
		// get only the number from the CAPEC ID
		String justTheCapecNumber = capec.substring(capec.indexOf("-")+1);
		//System.out.println("justTheCapecNumber " + justTheCapecNumber);

		for (int i = 0; i < capecsIdentified.size(); i++) {
			AttackPattern currentCapecIdentified = capecsIdentified.get(i);
			//System.out.println("currentCapecIdentified.iD " + currentCapecIdentified.iD);
			if (currentCapecIdentified.iD.equals(justTheCapecNumber)) {
				System.out.println("CAPEC: " + capec + " is in the capecsIdentified list");
				return true;
			}
		}
		System.out.println("CAPEC: " + capec + " is in NOT the capecsIdentified list");
		return false;
	}
	// ******************************** (end) methods to select Template Attack trees *************************************

	public void visualizeAttackTrees (CanPrecedeTree2 trees) {
		// for every tree
		for (int i = 0; i < trees.getNodes().size(); i++) {
			CanPrecedeNode2 currentTree = trees.getNodes().get(i);

			// create a node and an edge for all the nodes of the tree
			createNodesEdges(currentTree);
		}

		// print the Nodes and Edges that have been created
		for (int i = 0; i <nodes.size() ; i++) {
			System.out.println("Nodes "+nodes.get(i).getId());
		}
		for (int i = 0; i <edges.size() ; i++) {
			System.out.println("From " + edges.get(i).getFrom() + " to " + edges.get(i).getTo());
		}

	}

	public void createNodesEdges(CanPrecedeNode2 currentNode) {

		Node node = new Node();
		node.setId(currentNode.getId());
		node.setLabel(currentNode.getData());
		node.setExtendedDescription(currentNode.getExtendedDescription());
		node.setWidthConstraint(100);
		node.setHeightConstraint(100);
		node.setBorderWidth(0);
		node.setFont("14px arial white");
		node.setShape("box");

		switch (currentNode.getNodeType()) {
			case GATE:
				node.setShape("image");
				node.setLabel("");
				if (currentNode.getData().equals("AND")) {
					node.setImage("/images/andGate4.png");
					node.setColor("#A7BED3");
				} else {
					node.setImage("/images/orGate4.png");
					node.setColor("#A7BED3");
				}
				break;
			case CAPEC:
				node.setColor("#EE9B00");
				break;
			case STATE:
				if (currentNode.getParentId()==0) {
					node.setColor("#9B2226");
				} else {
					node.setColor("#E07102");
				}
				break;
			default:
				node.setColor("#f7e39c");
		}
		nodes.add(node);

		Edge edge = new Edge();
		edge.setFrom(currentNode.getParentId());
		edge.setTo(node.getId());
		edge.setColor("#0A9396");
		edge.setWidth(4);
		edges.add(edge);

		System.out.println("node: " + node.getLabel());
		System.out.println("edge: " + edge.getFrom() + " - " + edge.getTo());

		if (currentNode.getChildren().size() > 0) {
			for (int i = 0; i < currentNode.getChildren().size(); i++) {
				CanPrecedeNode2 currentChild = currentNode.getChildren().get(i);
				createNodesEdges(currentChild);
			}
		} else {

		}
	}

	// it works
	public void printCanPrecedeNode2(CanPrecedeNode2 node) {
		if (node.getChildren().size() > 0) {
			for (int i = 0; i < node.getChildren().size(); i++) {
				CanPrecedeNode2 currentChild = node.getChildren().get(i);
				printCanPrecedeNode2(currentChild);
			}
		} else {
			System.out.println(node);
			System.out.println(" ");
		}
	}

	// ******************************** (start) methods to be tested *************************************
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

	// not tested !
	@PostMapping(value = "/searchwithcves")
	public String searchWithCves(@RequestBody ArrayList<String> cveIds) {

		// do for every incoming CVE-ID
		for (int i = 0; i < cveIds.size(); i++) {

			// Put in the "cweFilteredArrayList" the CWEs that are related
			// to each of the CVE-IDs, searching the RVD Vulnerabilities
			ArrayList<String> cweFilteredArrayList = new ArrayList<>();
			for (int j = 0; j <rvdVulnerabilities.size() ; j++) {
				if (rvdVulnerabilities.get(j).cve.equals(cveIds.get(i))){
					cweFilteredArrayList.add(rvdVulnerabilities.get(j).cwe);
				}
			}
			// print the "cweFilteredArrayList"
			System.out.println(" ");
			System.out.println("cweFilteredArrayList: ");
			for (int j = 0; j < cweFilteredArrayList.size(); j++) {
				System.out.println(cweFilteredArrayList.get(j));
			}
			System.out.println(" ");

			// Put in the "capecsIdentified" list the CAPECs that are related
			// to each of the CWEs identified above, searching the CAPEC repo
			for (int j = 0; j < cweFilteredArrayList.size(); j++) {
				//remove the first 4 charactes eg: "CWE-115" becomes "115"
				String tempCWE=cweFilteredArrayList.get(i).substring(4);
				for (int k = 0; k < capecs.size(); k++) {
					AttackPattern tempCapec = capecs.get(j);
					for (int l = 0; l < tempCapec.related_Weaknesses.related_Weakness.size(); l++) {
						RelatedWeakness tempRelatedWeakness=tempCapec.related_Weaknesses.related_Weakness.get(k);
						if (tempRelatedWeakness.cWEID.equals(tempCWE)){
							capecsIdentified.add(tempCapec);
						}
					}
				}
			}

		}

		// print the list with the identified CAPECs
		System.out.println(" ");
		System.out.println("The following CAPECs have been identified as potential attacks related to list of incoming CVE-IDs:");
		if (capecsIdentified.size()>0) {
			for (int j = 0; j < capecsIdentified.size(); j++) {
				System.out.print(" " + capecsIdentified.get(j).iD);
			}
		}
		System.out.println(" ");

		// Put in the "canFollowGraphs" list all the attack trees
		// that are created based on the identified CAPECs
		for (int i = 0; i < capecsIdentified.size(); i++) {
			Graph graph = test(capecsIdentified.get(i));
			canFollowGraphs.add(graph);
		}
		// print the "canFollowGraphs"
		System.out.println(" ");
		System.out.println("canFollowGraphs: ");
		for (int i = 0; i < canFollowGraphs.size(); i++) {
			System.out.println(canFollowGraphs.get(i));
		}
		System.out.println(" ");

		return "rvdresult";
	}

	public Graph test(AttackPattern attackPattern) {

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

		// create the response and return it
		Graph canFollowGraph = new Graph();
		canFollowGraph.setNodes(nodes);
		canFollowGraph.setEdges(edges);
		return canFollowGraph;
	}

	@PostMapping(value = "/openvasreportinsert")
	public String openvasReportInsert(@RequestBody report reportXml) {

		System.out.println("openVAS report has been stored. ");
		return "rvdresult";
	}
	// ******************************** (end) methods to be tested *************************************

}
