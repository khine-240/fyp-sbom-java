package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.File;
import java.util.List;

// Pipeline:
//   Step 1: testset.json -> download each repo -> Syft (CycloneDX SBOM) -> Grype (matches) -> output/findings.json
//   Step 2: findings + frozen KEV/EPSS catalog -> output/enriched_findings.json (ranked by exploitability)
// Run with "--enrich-only" to skip Step 1 and reuse the existing output/findings.json.
public class Main {

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        // Create the folders we write into
        new File("repos").mkdirs();
        new File("output/sboms").mkdirs();
        new File("output/grype").mkdirs();

        JsonNode testset = mapper.readTree(new File("testset.json"));
        ArrayNode findings = mapper.createArrayNode();

        // "--enrich-only": skip scanning and reuse output/findings.json (Step 2 only)
        boolean enrichOnly = List.of(args).contains("--enrich-only");
        if (enrichOnly) {
            findings = (ArrayNode) mapper.readTree(new File("output/findings.json"));
            System.out.println("Using existing output/findings.json (" + findings.size() + " findings)");
        }

        for (JsonNode repo : enrichOnly ? mapper.createArrayNode() : testset.path("repos")) {
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

        if (!enrichOnly) {
            mapper.writeValue(new File("output/findings.json"), findings);
            System.out.println("\nDone. " + findings.size() + " findings written to output/findings.json");

            // 5. Print the summary table and save summary.csv + findings.csv
            ReportWriter.write(testset, findings);
        }

        // 6. Step 2: add EPSS + KEV and rank (only if catalog.json exists)
        if (new File("catalog.json").exists()) {
            Enricher.run(testset, findings);
        }
    }
}
