package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.PrintWriter;
import java.util.List;

// After the pipeline runs, prints a summary per repo and saves:
//   output/summary.csv  - one row per repo (packages, vulnerabilities, severity counts, fixable)
//   output/findings.csv - every finding, so it can be opened in Excel
public class ReportWriter {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final List<String> SEVERITIES = List.of("Critical", "High", "Medium", "Low", "Negligible", "Unknown");

    public static void write(JsonNode testset, JsonNode findings) throws Exception {
        PrintWriter csv = new PrintWriter("output/summary.csv");
        csv.println("repo,packages,vulnerabilities,critical,high,medium,low,negligible,unknown,fixable");

        System.out.println("\n================ SUMMARY ================");
        System.out.printf("%-10s %8s %6s %5s %5s %5s %5s %5s %5s %8s%n",
                "repo", "packages", "vulns", "crit", "high", "med", "low", "negl", "unkn", "fixable");

        int totalPackages = 0, totalVulns = 0;
        for (JsonNode repo : testset.path("repos")) {
            String name = repo.path("name").asText();
            File sbom = new File("output/sboms/" + name + ".cdx.json");
            if (!sbom.exists()) continue;   // this repo failed, skip it

            // Packages = number of components in the CycloneDX SBOM
            int packages = mapper.readTree(sbom).path("components").size();

            // Count this repo's findings by severity, and how many have a fix
            int vulns = 0, fixable = 0;
            int[] sev = new int[SEVERITIES.size()];
            for (JsonNode f : findings) {
                if (!f.path("repo").asText().equals(name)) continue;
                vulns++;
                if (f.path("fix_state").asText().equals("fixed")) fixable++;
                int i = SEVERITIES.indexOf(f.path("severity").asText());
                sev[i >= 0 ? i : SEVERITIES.size() - 1]++;
            }

            System.out.printf("%-10s %8s %6s %5s %5s %5s %5s %5s %5s %8s%n",
                    name, d(packages), d(vulns), d(sev[0]), d(sev[1]), d(sev[2]),
                    d(sev[3]), d(sev[4]), d(sev[5]), d(fixable));
            csv.printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d%n",
                    name, packages, vulns, sev[0], sev[1], sev[2], sev[3], sev[4], sev[5], fixable);
            totalPackages += packages;
            totalVulns += vulns;
        }
        System.out.printf("%-10s %8s %6s%n", "TOTAL", d(totalPackages), d(totalVulns));
        csv.close();

        writeFindingsCsv(findings);
        System.out.println("\nSaved output/summary.csv and output/findings.csv");
    }

    // Show "-" instead of 0 in the terminal table (the CSV keeps real numbers)
    private static String d(int n) {
        return n == 0 ? "-" : String.valueOf(n);
    }

    // One row per finding with the 10 agreed fields (lists joined with ';')
    private static void writeFindingsCsv(JsonNode findings) throws Exception {
        String[] cols = {"repo", "language", "package", "version", "package_type",
                "vuln_id", "cve_ids", "severity", "fix_state", "fix_versions"};
        PrintWriter out = new PrintWriter("output/findings.csv");
        out.println(String.join(",", cols));
        for (JsonNode f : findings) {
            StringBuilder row = new StringBuilder();
            for (int i = 0; i < cols.length; i++) {
                JsonNode v = f.path(cols[i]);
                String text;
                if (v.isArray()) {
                    StringBuilder sb = new StringBuilder();
                    for (JsonNode x : v) { if (sb.length() > 0) sb.append(';'); sb.append(x.asText()); }
                    text = sb.toString();
                } else {
                    text = v.asText();
                }
                if (text.contains(",") || text.contains("\"")) text = "\"" + text.replace("\"", "\"\"") + "\"";
                if (i > 0) row.append(',');
                row.append(text);
            }
            out.println(row);
        }
        out.close();
    }
}
