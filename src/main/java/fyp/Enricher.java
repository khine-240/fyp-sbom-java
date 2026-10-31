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

// Step 2: adds EPSS score + CISA KEV status to every Step 1 finding, then ranks them by exploitability.
//   Ranking rule: 1) in KEV first  2) higher EPSS score  3) higher severity
//   Several CVEs in one finding: use the HIGHEST EPSS; in_kev = true if ANY of its CVEs is in KEV.
//   No CVE (GHSA only): no EPSS, not in KEV, ranked after findings with a score.
// Saves output/enriched_findings.json, output/ranked_findings.csv, output/enrichment_info.json
public class Enricher {

    private static final List<String> SEV = List.of("Critical", "High", "Medium", "Low", "Negligible", "Unknown");

    public static void run(JsonNode testset, ArrayNode findings) throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        System.out.println("\n================ STEP 2: EPSS + KEV ================");

        // 1. Load the frozen catalog and check it
        Catalog cat = new Catalog("catalog.json");
        System.out.println("Catalog: " + cat.dir + " (checking fingerprints)");
        cat.verify();
        Set<String> wanted = new HashSet<>();
        for (JsonNode f : findings) f.path("cve_ids").forEach(c -> wanted.add(c.asText()));
        cat.loadKev();
        cat.loadEpss(wanted);
        System.out.printf("KEV catalog %s: %d exploited CVEs%n", cat.kevVersion, cat.kevTotal);
        System.out.printf("EPSS %s (model %s): %d CVEs scored%n", cat.epssScoreDate, cat.epssModel, cat.epssTotal);

        // 2. Cross-check a sample with the live EPSS API
        String apiResult = ApiCheck.run(cat, 10);
        System.out.println("EPSS API cross-check: " + apiResult);

        // 3. Add the new fields to every finding
        List<ObjectNode> list = new ArrayList<>();
        for (JsonNode node : findings) {
            ObjectNode f = ((ObjectNode) node).deepCopy();
            Catalog.Epss best = null;
            String kevDate = null, ransomware = null;
            for (JsonNode c : f.path("cve_ids")) {
                Catalog.Epss e = cat.epss.get(c.asText());
                if (e != null && (best == null || e.score() > best.score())) best = e;
                Catalog.Kev k = cat.kev.get(c.asText());
                if (k != null && (kevDate == null || k.dateAdded().compareTo(kevDate) < 0)) {
                    kevDate = k.dateAdded();
                    ransomware = k.ransomware();
                }
            }
            if (best != null) {
                f.put("epss_score", best.score());
                f.put("epss_percentile", best.percentile());
            } else {
                f.putNull("epss_score");
                f.putNull("epss_percentile");
            }
            f.put("in_kev", kevDate != null);
            if (kevDate != null) f.put("kev_date_added", kevDate); else f.putNull("kev_date_added");
            if (ransomware != null) f.put("kev_ransomware", ransomware); else f.putNull("kev_ransomware");
            list.add(f);
        }

        // 4. Rank: KEV first -> higher EPSS -> higher severity (then by repo/package so the order never changes)
        list.sort((a, b) -> {
            int c = Boolean.compare(b.path("in_kev").asBoolean(), a.path("in_kev").asBoolean());
            if (c != 0) return c;
            double ea = a.path("epss_score").isNull() ? -1 : a.path("epss_score").asDouble();
            double eb = b.path("epss_score").isNull() ? -1 : b.path("epss_score").asDouble();
            c = Double.compare(eb, ea);
            if (c != 0) return c;
            c = sevRank(a) - sevRank(b);
            if (c != 0) return c;
            c = a.path("repo").asText().compareTo(b.path("repo").asText());
            if (c != 0) return c;
            c = a.path("package").asText().compareTo(b.path("package").asText());
            if (c != 0) return c;
            return a.path("vuln_id").asText().compareTo(b.path("vuln_id").asText());
        });
        ArrayNode ranked = mapper.createArrayNode();
        int rank = 1;
        for (ObjectNode f : list) {
            f.put("rank", rank++);
            ranked.add(f);
        }

        // 5. Save the outputs
        mapper.writeValue(new File("output/enriched_findings.json"), ranked);
        writeCsv(ranked);
        ObjectNode info = mapper.createObjectNode();
        info.put("catalog_dir", cat.dir);
        info.put("kev_catalog_version", cat.kevVersion);
        info.put("epss_score_date", cat.epssScoreDate);
        info.put("epss_model_version", cat.epssModel);
        info.put("fingerprints", "all OK (SHA256SUMS)");
        info.put("api_cross_check", apiResult);
        info.put("ranking_rule", "in_kev first, then epss_score high to low, then severity");
        mapper.writeValue(new File("output/enrichment_info.json"), info);

        printSummary(testset, ranked);
        System.out.println("\nSaved output/enriched_findings.json, output/ranked_findings.csv, output/enrichment_info.json");
    }

    private static int sevRank(JsonNode f) {
        int i = SEV.indexOf(f.path("severity").asText());
        return i >= 0 ? i : SEV.size();
    }

    // Overview per repo + the top 15 findings
    private static void printSummary(JsonNode testset, ArrayNode ranked) {
        int withCve = 0, withEpss = 0, kev = 0, high = 0;
        Set<String> kevCves = new HashSet<>();
        Map<String, int[]> perRepo = new LinkedHashMap<>();       // findings, in KEV, EPSS>=0.1
        Map<String, Double> maxEpss = new LinkedHashMap<>();
        for (JsonNode r : testset.path("repos")) { perRepo.put(r.path("name").asText(), new int[3]); maxEpss.put(r.path("name").asText(), 0.0); }
        for (JsonNode f : ranked) {
            if (f.path("cve_ids").size() > 0) withCve++;
            boolean hasEpss = !f.path("epss_score").isNull();
            if (hasEpss) withEpss++;
            int[] c = perRepo.computeIfAbsent(f.path("repo").asText(), k -> new int[3]);
            c[0]++;
            if (f.path("in_kev").asBoolean()) {
                kev++; c[1]++;
                f.path("cve_ids").forEach(x -> kevCves.add(x.asText()));
            }
            if (hasEpss && f.path("epss_score").asDouble() >= 0.1) { high++; c[2]++; }
            if (hasEpss) maxEpss.merge(f.path("repo").asText(), f.path("epss_score").asDouble(), Math::max);
        }
        System.out.printf("%nFindings: %d | with a CVE: %d | with an EPSS score: %d | in KEV: %d | EPSS >= 0.1: %d%n",
                ranked.size(), withCve, withEpss, kev, high);

        System.out.println("\n--- Per repo ---");
        System.out.printf("%-12s %8s %7s %10s %9s%n", "repo", "findings", "in KEV", "EPSS>=0.1", "max EPSS");
        for (Map.Entry<String, int[]> e : perRepo.entrySet()) {
            int[] c = e.getValue();
            System.out.printf("%-12s %8d %7s %10s %9.5f%n", e.getKey(), c[0],
                    c[1] == 0 ? "-" : c[1], c[2] == 0 ? "-" : c[2], maxEpss.getOrDefault(e.getKey(), 0.0));
        }

        System.out.println("\n--- Top 15 (fix these first) ---");
        String row = "%4s  %-10s %-24s %-12s %-18s %-8s %4s %8s%n";
        System.out.printf(row, "rank", "repo", "package", "version", "cve", "severity", "KEV", "EPSS");
        for (int i = 0; i < Math.min(15, ranked.size()); i++) {
            JsonNode f = ranked.get(i);
            String cve = f.path("cve_ids").size() > 0 ? f.path("cve_ids").get(0).asText() : f.path("vuln_id").asText();
            String ep = f.path("epss_score").isNull() ? "-" : String.format("%.5f", f.path("epss_score").asDouble());
            System.out.printf(row, f.path("rank").asInt(), cut(f.path("repo").asText(), 10), cut(f.path("package").asText(), 24),
                    cut(f.path("version").asText(), 12), cut(cve, 18), f.path("severity").asText(),
                    f.path("in_kev").asBoolean() ? "YES" : "-", ep);
        }
    }

    // Ranked list for Excel
    private static void writeCsv(ArrayNode ranked) throws Exception {
        String[] cols = {"rank", "repo", "package", "version", "package_type", "vuln_id", "cve_ids", "severity",
                "in_kev", "kev_date_added", "kev_ransomware", "epss_score", "epss_percentile", "fix_state", "fix_versions"};
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

    private static String cut(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 1) + "~"; }
}
