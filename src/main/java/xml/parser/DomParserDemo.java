package xml.parser;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import rvd.model.RvdVulnerability;

public class DomParserDemo {

    public static ArrayList<String> openVasCves = new ArrayList<>();

    public static void main(String[] args) {

        try {
            File inputFile = new File("input.xml");
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(inputFile);
            doc.getDocumentElement().normalize();
            System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
            NodeList nList = doc.getElementsByTagName("ref");
            System.out.println("----------------------------");

            for (int temp = 0; temp < nList.getLength(); temp++) {
                Node nNode = nList.item(temp);
                //System.out.println("\nCurrent Element :" + nNode.getNodeName());

                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;

                    if (eElement.getAttribute("type").contains("cve")) {
                        openVasCves.add(eElement.getAttribute("id"));
                        //System.out.println("ref id : " + eElement.getAttribute("id"));
                    }
                }
            }

            // print openVasCves arraylist
            System.out.println("openVasCves: ");
            for (int i = 0; i < openVasCves.size(); i++) {
                System.out.println("CVE " + i + ": " + openVasCves.get(i));
            }

            // run cve.search for every CVE in openVasCves arraylist
            String commandResponse = "";
            String fileName = "cveSearchOutput.json";
            for (int i = 0; i < openVasCves.size(); i++) {
                commandResponse = executeCommand(openVasCves.get(i), fileName);
                System.out.println("Call executeCommand() method for CVE: " + openVasCves.get(i) + " Response: " + commandResponse);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String executeCommand(String cve, String fileName) {

        // use ProcessBuilder to execute external shell commands
        ProcessBuilder processBuilder = new ProcessBuilder();

        // run the cve-search command and get the response
        processBuilder.command("bash", "-c", "./bin/search.py -c " + cve + " -a -o json >> " + fileName);
        try {
            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

            int exitVal = process.waitFor();
            if (exitVal == 0) {
                System.out.println("Success! Command has been executed!");
                return output.toString();
            } else {
                //abnormal...
                return "Command has not been executed";
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        return "executeCommand method";
    }
}
