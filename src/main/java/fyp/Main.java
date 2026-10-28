package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.File;
import java.util.List;

// Step 1 pipeline:
//   testset.json -> git clone each repo -> Syft (CycloneDX SBOM) -> Grype (matches) -> output/findings.json
public class Main {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        // Create the folders we write into
        new File("repos").mkdirs();
        new File("output/sboms").mkdirs();
        new File("output/grype").mkdirs();

        JsonNode testset = mapper.readTree(new File("testset.json"));
        ArrayNode findings = mapper.createArrayNode();

        for (JsonNode repo : testset.path("repos")) {
            String name = repo.path("name").asText();
            String url = repo.path("url").asText();
            System.out.println("\n=== " + name + " ===");

            String repoDir = "repos/" + name;
            String sbomFile = "output/sboms/" + name + ".cdx.json";
            String grypeFile = "output/grype/" + name + ".grype.json";

            try {
                // 1. Download the repo (skip if already downloaded)
                //    If testset.json gives a "commit", download exactly that frozen version.
                String commit = repo.path("commit").asText("");
                if (!CommandRunner.exists(repoDir)) {
                    if (commit.isEmpty()) {
                        CommandRunner.run(List.of("git", "clone", "--depth", "1", url, repoDir));
                    } else {
                        CommandRunner.run(List.of("git", "init", "-q", repoDir));
                        CommandRunner.run(List.of("git", "-C", repoDir, "remote", "add", "origin", url));
                        CommandRunner.run(List.of("git", "-C", repoDir, "fetch", "-q", "--depth", "1", "origin", commit));
                        CommandRunner.run(List.of("git", "-C", repoDir, "checkout", "-q", "FETCH_HEAD"));
                    }
                }
                if (!commit.isEmpty()) System.out.println("  pinned at commit " + commit);

                // 2. Syft: make the CycloneDX SBOM
                CommandRunner.run(List.of("syft", "scan", "dir:" + repoDir,
                        "-o", "cyclonedx-json=" + sbomFile, "-q"));

                // 3. Grype: match the SBOM against the vulnerability database
                CommandRunner.run(List.of("grype", "sbom:" + sbomFile,
                        "-o", "json", "--file", grypeFile, "-q"));

                // 4. Convert Grype's output into our findings format
                int before = findings.size();
                FindingParser.addFindings(name, new File(grypeFile), findings);
                System.out.println("  -> " + (findings.size() - before) + " findings");

            } catch (Exception e) {
                System.out.println("  FAILED: " + e.getMessage() + " (skipping this repo)");
            }
        }

        mapper.writeValue(new File("output/findings.json"), findings);
        System.out.println("\nDone. " + findings.size() + " findings written to output/findings.json");

        // 5. Print the summary table and save summary.csv + findings.csv
        ReportWriter.write(testset, findings);
    }
}
