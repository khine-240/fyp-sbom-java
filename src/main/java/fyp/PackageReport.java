package fyp;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

// Groups the findings by package + version, so you can see for each vulnerable package:
//   how many vulnerabilities it has, how many have a fix, and which version to upgrade to.
// Saves output/packages.csv and prints a short per-repo overview.
//
// Note: "fixed" in Grype means a FIXED VERSION EXISTS (upgrade available).
//       The repo itself still uses the vulnerable version.
public class PackageReport {

    // Everything we collect for one package + version in one repo
    static class Pkg {
        String repo, name, version, type;
        int vulns, critical, high, medium, low, fixable, notFixed;
        TreeSet<String> allFixVersions = new TreeSet<>(PackageReport::compareVersions);
        String upgradeTo = "";   // lowest version that fixes all fixable vulnerabilities
    }

    public static void write(JsonNode testset, JsonNode findings) throws Exception {
        // 1. Group findings by repo | package | version
        Map<String, Pkg> pkgs = new LinkedHashMap<>();
        for (JsonNode f : findings) {
            String key = f.path("repo").asText() + "|" + f.path("package").asText() + "|" + f.path("version").asText();
            Pkg p = pkgs.computeIfAbsent(key, k -> {
                Pkg n = new Pkg();
                n.repo = f.path("repo").asText();
                n.name = f.path("package").asText();
                n.version = f.path("version").asText();
                n.type = f.path("package_type").asText();
                return n;
            });
            p.vulns++;
            switch (f.path("severity").asText()) {
                case "Critical": p.critical++; break;
                case "High":     p.high++;     break;
                case "Medium":   p.medium++;   break;
                case "Low":      p.low++;      break;
                default: break;
            }
            List<String> fixes = new ArrayList<>();
            f.path("fix_versions").forEach(v -> fixes.add(v.asText()));
            if (f.path("fix_state").asText().equals("fixed") && !fixes.isEmpty()) {
                p.fixable++;
                p.allFixVersions.addAll(fixes);
                // For this vulnerability, the smallest fix version that is newer than what we use
                String best = null;
                for (String v : fixes) {
                    if (compareVersions(v, p.version) > 0 && (best == null || compareVersions(v, best) < 0)) best = v;
                }
                if (best == null) best = fixes.get(0);
                // The package must be upgraded to the HIGHEST of these to fix everything
                if (p.upgradeTo.isEmpty() || compareVersions(best, p.upgradeTo) > 0) p.upgradeTo = best;
            } else {
                p.notFixed++;
            }
        }

        // 2. Save output/packages.csv (one row per vulnerable package + version)
        PrintWriter out = new PrintWriter("output/packages.csv");
        out.println("repo,package,version,package_type,vulnerabilities,critical,high,medium,low,"
                + "fixable,not_fixed,status,upgrade_to,all_fix_versions");
        for (Pkg p : pkgs.values()) {
            out.println(String.join(",", q(p.repo), q(p.name), q(p.version), q(p.type),
                    "" + p.vulns, "" + p.critical, "" + p.high, "" + p.medium, "" + p.low,
                    "" + p.fixable, "" + p.notFixed, status(p), q(p.upgradeTo),
                    q(String.join(";", p.allFixVersions))));
        }
        out.close();

        // 3. Print a short overview per repo
        System.out.println("\n================ PACKAGES ================");
        System.out.printf("%-10s %9s %10s %9s %7s%n", "repo", "vuln pkgs", "fix avail", "partial", "no fix");
        for (JsonNode repo : testset.path("repos")) {
            String name = repo.path("name").asText();
            int total = 0, full = 0, partial = 0, none = 0;
            for (Pkg p : pkgs.values()) {
                if (!p.repo.equals(name)) continue;
                total++;
                switch (status(p)) {
                    case "fix available": full++; break;
                    case "partial fix":   partial++; break;
                    default:              none++; break;
                }
            }
            if (total == 0) continue;
            System.out.printf("%-10s %9d %10d %9d %7d%n", name, total, full, partial, none);
        }
        System.out.println("\nSaved output/packages.csv (one row per vulnerable package + version)");
    }

    // fix available = every vulnerability has a fix; partial = some do; no fix = none do
    static String status(Pkg p) {
        if (p.notFixed == 0) return "fix available";
        if (p.fixable > 0) return "partial fix";
        return "no fix";
    }

    // Compare versions like 1.4.5 < 1.4.18 < 2.0 (numbers compared as numbers, not text)
    static int compareVersions(String a, String b) {
        String[] x = a.split("[.\\-+_]"), y = b.split("[.\\-+_]");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            String s = i < x.length ? x[i] : "0", t = i < y.length ? y[i] : "0";
            int c;
            if (s.matches("\\d+") && t.matches("\\d+")) {
                c = Long.compare(Long.parseLong(s), Long.parseLong(t));
            } else {
                c = s.compareTo(t);
            }
            if (c != 0) return c;
        }
        return 0;
    }

    // Quote text for CSV if it contains a comma or quote
    private static String q(String s) {
        if (s.contains(",") || s.contains("\"")) return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }
}
