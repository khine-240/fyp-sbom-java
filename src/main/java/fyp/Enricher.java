package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

// Step 2: adds EPSS + CISA KEV to every Step 1 finding (team fields), then ranks them by exploitability.
//   Ranking rule: 1) in KEV first  2) higher EPSS score  3) higher EPSS percentile  4) higher severity
//   Several CVEs in one finding: use the HIGHEST EPSS (epss_cve says which CVE); in_kev = true if ANY CVE is in KEV.
//   No CVE (GHSA only): cve_source "none", no EPSS, not in KEV -> "P5 - no EPSS score".
// Saves output/enriched_findings.json, output/ranked_findings.csv, output/step2_metadata.json
public class Enricher {

    private static final List<String> SEV = List.of("Critical", "High", "Medium", "Low", "Negligible", "Unknown");
    public static final List<String> PRIORITIES = List.of("P1 - in CISA KEV", "P2 - EPSS >= 10%",
            "P3 - EPSS 1-10%", "P4 - EPSS < 1%", "P5 - no EPSS score");

    public static void run(JsonNode testset, ArrayNode findings) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        System.out.println("\n================ STEP 2: EPSS + KEV ================");

        // 1. Load the team catalog snapshot and check it
        Catalog cat = new Catalog("catalog.json");
        System.out.println("Catalog: " + cat.dir + " (checking fingerprints)");
        cat.verify();
        Set<String> wanted = new HashSet<>();
        for (JsonNode f : findings) f.path("cve_ids").forEach(c -> wanted.add(c.asText()));
        cat.loadKev();
        cat.loadEpss(wanted);
        System.out.printf("KEV catalog %s: %d exploited CVEs%n", cat.kevVersion, cat.kevTotal);
        System.out.printf("EPSS %s (model %s): %d CVEs scored%n", cat.epssScoreDate, cat.epssModel, cat.epssTotal);

        // 2. Cross-check a sample with the live EPSS API (same day as the catalog's scores)
        String apiResult = ApiCheck.run(cat, 10);
        System.out.println("EPSS API cross-check: " + apiResult);

        // 3. Add the team's Step 2 fields to every finding
        List<ObjectNode> list = new ArrayList<>();
        for (JsonNode node : findings) {
            ObjectNode f = ((ObjectNode) node).deepCopy();
            Catalog.Epss best = null;
            String bestCve = null;
            Catalog.Kev kevHit = null;
            for (JsonNode c : f.path("cve_ids")) {
                String cve = c.asText();
                Catalog.Epss e = cat.epss.get(cve);
                if (e != null && (best == null || e.score() > best.score())) { best = e; bestCve = cve; }
                Catalog.Kev k = cat.kev.get(cve);
                if (k != null && (kevHit == null || k.dateAdded().compareTo(kevHit.dateAdded()) < 0)) kevHit = k;
            }
            f.put("cve_source", f.path("cve_ids").size() > 0 ? "grype" : "none");
            if (best != null) {
                f.put("epss_score", best.score());
                f.put("epss_percentile", best.percentile());
                f.put("epss_cve", bestCve);
            } else {
                f.putNull("epss_score");
                f.putNull("epss_percentile");
                f.putNull("epss_cve");
            }
            f.put("in_kev", kevHit != null);
            putOrNull(f, "kev_date_added", kevHit == null ? null : kevHit.dateAdded());
            putOrNull(f, "kev_due_date", kevHit == null ? null : kevHit.dueDate());
            putOrNull(f, "kev_ransomware_use", kevHit == null ? null : kevHit.ransomware());
            f.put("priority", priority(kevHit != null, best));
            list.add(f);
        }

        // 4. Rank: KEV first -> higher EPSS -> higher percentile -> higher severity (then repo/package/ID so the order never changes)
        list.sort((a, b) -> {
            int c = Boolean.compare(b.path("in_kev").asBoolean(), a.path("in_kev").asBoolean());
            if (c != 0) return c;
            c = Double.compare(num(b, "epss_score"), num(a, "epss_score"));
            if (c != 0) return c;
            c = Double.compare(num(b, "epss_percentile"), num(a, "epss_percentile"));
            if (c != 0) return c;
            c = sevRank(a) - sevRank(b);
            if (c != 0) return c;
            c = a.path("repo").asText().compareTo(b.path("repo").asText());
            if (c != 0) return c;
            c = a.path("package").asText().compareTo(b.path("package").asText());
            if (c != 0) return c;
            c = a.path("version").asText().compareTo(b.path("version").asText());
            if (c != 0) return c;
            return a.path("vuln_id").asText().compareTo(b.path("vuln_id").asText());
        });
        ArrayNode ranked = mapper.createArrayNode();
        int rank = 1;
        for (ObjectNode f : list) {
            f.put("exploitability_rank", rank++);
            ranked.add(f);
        }

        // 5. Save the outputs
        mapper.writeValue(new File("output/enriched_findings.json"), ranked);
        writeCsv(ranked);
        ObjectNode meta = mapper.createObjectNode();
        meta.put("catalog_repo", "https://github.com/caffeineintaker/fyp-vuln-catalog");
        meta.put("snapshot", cat.snapshot);
        meta.put("kev_catalog_version", cat.kevVersion);
        meta.put("kev_count", cat.kevTotal);
        meta.put("epss_score_date", cat.epssScoreDate);
        meta.put("epss_model_version", cat.epssModel);
        meta.put("epss_count", cat.epssTotal);
        meta.put("fingerprints", "all OK (manifest.json SHA-256)");
        meta.put("api_cross_check", apiResult);
        meta.put("ranking_rule", "in_kev first, then epss_score, then epss_percentile (high to low), then severity");
        meta.put("findings", ranked.size());
        ObjectNode byP = meta.putObject("findings_by_priority");
        for (String p : PRIORITIES) byP.put(p, 0);
        for (JsonNode f : ranked) byP.put(f.path("priority").asText(), byP.path(f.path("priority").asText()).asInt() + 1);
        mapper.writeValue(new File("output/step2_metadata.json"), meta);

        printSummary(testset, ranked);
        System.out.println("\nSaved output/enriched_findings.json, output/ranked_findings.csv, output/step2_metadata.json");
    }

    // P1-P5 label, exactly as agreed by the team
    static String priority(boolean inKev, Catalog.Epss e) {
        if (inKev) return PRIORITIES.get(0);
        if (e == null) return PRIORITIES.get(4);
        if (e.score() >= 0.10) return PRIORITIES.get(1);
        if (e.score() >= 0.01) return PRIORITIES.get(2);
        return PRIORITIES.get(3);
    }

    private static double num(JsonNode f, String field) {
        return f.path(field).isNull() || f.path(field).isMissingNode() ? -1 : f.path(field).asDouble();
    }

    private static void putOrNull(ObjectNode f, String field, String value) {
        if (value == null) f.putNull(field); else f.put(field, value);
    }

    private static int sevRank(JsonNode f) {
        int i = SEV.indexOf(f.path("severity").asText());
        return i >= 0 ? i : SEV.size();
    }

    // Priority totals, overview per repo, and the top 15 findings
    private static void printSummary(JsonNode testset, ArrayNode ranked) {
        Map<String, int[]> perRepo = new LinkedHashMap<>();          // count per priority P1..P5
        for (JsonNode r : testset.path("repos")) perRepo.put(r.path("name").asText(), new int[5]);
        int[] total = new int[5];
        for (JsonNode f : ranked) {
            int p = PRIORITIES.indexOf(f.path("priority").asText());
            total[p]++;
            perRepo.computeIfAbsent(f.path("repo").asText(), k -> new int[5])[p]++;
        }
        System.out.println("\n--- Findings by priority ---");
        for (int i = 0; i < 5; i++) System.out.printf("%-20s %5d%n", PRIORITIES.get(i), total[i]);
        System.out.printf("%-20s %5d%n", "Total", ranked.size());

        System.out.println("\n--- Per repo ---");
        System.out.printf("%-12s %5s %5s %5s %5s %5s %6s%n", "repo", "P1", "P2", "P3", "P4", "P5", "total");
        for (Map.Entry<String, int[]> e : perRepo.entrySet()) {
            int[] c = e.getValue();
            System.out.printf("%-12s %5s %5s %5s %5s %5s %6d%n", e.getKey(), d(c[0]), d(c[1]), d(c[2]), d(c[3]), d(c[4]),
                    c[0] + c[1] + c[2] + c[3] + c[4]);
        }

        System.out.println("\n--- Top 15 (fix these first) ---");
        String row = "%4s  %-17s %-10s %-20s %-10s %-16s %-8s %8s%n";
        System.out.printf(row, "rank", "priority", "repo", "package", "version", "epss_cve", "severity", "EPSS");
        for (int i = 0; i < Math.min(15, ranked.size()); i++) {
            JsonNode f = ranked.get(i);
            String cve = f.path("epss_cve").isNull() ? f.path("vuln_id").asText() : f.path("epss_cve").asText();
            String ep = f.path("epss_score").isNull() ? "-" : String.format("%.5f", f.path("epss_score").asDouble());
            System.out.printf(row, f.path("exploitability_rank").asInt(), f.path("priority").asText(),
                    cut(f.path("repo").asText(), 10), cut(f.path("package").asText(), 20),
                    cut(f.path("version").asText(), 10), cut(cve, 16), f.path("severity").asText(), ep);
        }
    }

    // Ranked list for Excel
    private static void writeCsv(ArrayNode ranked) throws Exception {
        String[] cols = {"exploitability_rank", "priority", "repo", "package", "version", "package_type", "vuln_id",
                "cve_ids", "severity", "cve_source", "epss_score", "epss_percentile", "epss_cve", "in_kev",
                "kev_date_added", "kev_due_date", "kev_ransomware_use", "fix_state", "fix_versions"};
        try (PrintWriter out = new PrintWriter("output/ranked_findings.csv")) {
            out.println(String.join(",", cols));
            for (JsonNode f : ranked) {
                List<String> vals = new ArrayList<>();
                for (String c : cols) {
                    JsonNode v = f.path(c);
                    String s;
                    if (v.isArray()) {
                        List<String> parts = new ArrayList<>();
                        v.forEach(x -> parts.add(x.asText()));
                        s = String.join(";", parts);
                    } else if (v.isNull() || v.isMissingNode()) {
                        s = "";
                    } else {
                        s = v.asText();
                    }
                    if (s.contains(",") || s.contains("\"")) s = "\"" + s.replace("\"", "\"\"") + "\"";
                    vals.add(s);
                }
                out.println(String.join(",", vals));
            }
        }
    }

    private static String d(int n) { return n == 0 ? "-" : String.valueOf(n); }

    private static String cut(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 1) + "~"; }
}
