package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.Set;

// Reads one <repo>.grype.json file and turns every match into one finding
// with the team's agreed fields.
public class FindingParser {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static void addFindings(String repo, File grypeJson, ArrayNode findings) throws Exception {
        JsonNode root = mapper.readTree(grypeJson);

        for (JsonNode match : root.path("matches")) {
            JsonNode vuln = match.path("vulnerability");
            JsonNode pkg = match.path("artifact");

            ObjectNode f = findings.addObject();
            f.put("repo", repo);
            f.put("language", languageOf(pkg.path("type").asText()));
            f.put("package", pkg.path("name").asText());
            f.put("version", pkg.path("version").asText());
            f.put("package_type", pkg.path("type").asText());
            f.put("vuln_id", vuln.path("id").asText());
            f.set("cve_ids", cveIds(match));
            f.put("severity", vuln.path("severity").asText("Unknown"));
            f.put("fix_state", vuln.path("fix").path("state").asText("unknown"));
            f.set("fix_versions", vuln.path("fix").path("versions"));
        }
    }

    // Collect every CVE number for this match (Grype may report a GHSA id
    // with the CVE listed under relatedVulnerabilities).
    private static ArrayNode cveIds(JsonNode match) {
        Set<String> ids = new LinkedHashSet<>();
        String mainId = match.path("vulnerability").path("id").asText();
        if (mainId.startsWith("CVE-")) ids.add(mainId);
        for (JsonNode related : match.path("relatedVulnerabilities")) {
            String id = related.path("id").asText();
            if (id.startsWith("CVE-")) ids.add(id);
        }
        ArrayNode arr = mapper.createArrayNode();
        ids.forEach(arr::add);
        return arr;
    }

    // Turn Syft's package type into a programming language name.
    static String languageOf(String packageType) {
        switch (packageType) {
            case "java-archive": case "jenkins-plugin": case "graalvm-native-image": return "java";
            case "npm": return "javascript";
            case "python": return "python";
            case "go-module": return "go";
            case "gem": return "ruby";
            case "rust-crate": return "rust";
            case "php-composer": return "php";
            case "dotnet": return "csharp";
            case "deb": case "rpm": case "apk": return "os-package";
            default: return "other";
        }
    }
}
