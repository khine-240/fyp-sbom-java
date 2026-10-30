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
// Saves output/packages.csv and prints every vulnerable package per repo, with its CVEs.
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
        List<String[]> vulnList = new ArrayList<>();   // {cve(s), severity, fix text, vuln_id}
        TreeSet<String> cves = new TreeSet<>();
    }

    private static final List<String> SEV_ORDER = List.of("Critical", "High", "Medium", "Low", "Negligible", "Unknown");

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

            // Remember this vulnerability for the detailed list (show CVE numbers when there are any)
            List<String> cveList = new ArrayList<>();
            f.path("cve_ids").forEach(c -> cveList.add(c.asText()));
            p.cves.addAll(cveList);
            String vulnId = f.path("vuln_id").asText();
            String shown = cveList.isEmpty() ? vulnId : String.join(", ", cveList);
            boolean hasFix = f.path("fix_state").asText().equals("fixed") && !fixes.isEmpty();
            String fixText = hasFix ? "fixed in " + String.join(", ", fixes)
                                    : "no fix (" + f.path("fix_state").asText() + ")";
            p.vulnList.add(new String[]{shown, f.path("severity").asText(), fixText,
                    (cveList.isEmpty() || vulnId.startsWith("CVE-")) ? "" : vulnId});
            if (hasFix) {
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
                + "fixable,not_fixed,status,upgrade_to,all_fix_versions,cve_ids");
        for (Pkg p : pkgs.values()) {
            out.println(String.join(",", q(p.repo), q(p.name), q(p.version), q(p.type),
                    "" + p.vulns, "" + p.critical, "" + p.high, "" + p.medium, "" + p.low,
                    "" + p.fixable, "" + p.notFixed, status(p), q(p.upgradeTo),
                    q(String.join(";", p.allFixVersions)), q(String.join(";", p.cves))));
        }
        out.close();

        // 3. Print every vulnerable package per repo (riskiest first), with its CVEs underneath
        System.out.println("\n================ VULNERABLE PACKAGES ================");
        String row = "%-34s %-16s %5s %4s %4s %4s %4s  %-14s %s%n";
        for (JsonNode repo : testset.path("repos")) {
            String name = repo.path("name").asText();
            List<Pkg> list = new ArrayList<>();
            for (Pkg p : pkgs.values()) if (p.repo.equals(name)) list.add(p);
            if (list.isEmpty()) continue;
            list.sort((a, b) -> a.critical != b.critical ? b.critical - a.critical
                              : a.high != b.high ? b.high - a.high : b.vulns - a.vulns);

            System.out.println("\n--- " + name + " (" + list.size() + " vulnerable packages) ---");
            System.out.printf(row, "package", "version", "vulns", "crit", "high", "med", "low", "fix status", "upgrade to");
            int full = 0, partial = 0, none = 0;
            for (Pkg p : list) {
                System.out.printf(row, cut(p.name, 34), cut(p.version, 16), p.vulns, dash(p.critical), dash(p.high),
                        dash(p.medium), dash(p.low), status(p), p.upgradeTo.isEmpty() ? "-" : p.upgradeTo);
                // Under each package: its vulnerabilities, Critical first
                p.vulnList.sort((a, b) -> sevRank(a[1]) - sevRank(b[1]));
                for (String[] v : p.vulnList) {
                    System.out.printf("      - %-28s %-9s %-30s %s%n", v[0], v[1], v[2], v[3]);
                }
                switch (status(p)) {
                    case "fix available": full++; break;
                    case "partial fix":   partial++; break;
                    default:              none++; break;
                }
            }
            System.out.printf("  => %d fix available, %d partial fix, %d no fix%n", full, partial, none);
        }
        System.out.println("\nSaved output/packages.csv (one row per vulnerable package + version)");
    }

    private static int sevRank(String s) {
        int i = SEV_ORDER.indexOf(s);
        return i >= 0 ? i : SEV_ORDER.size();
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

    // Show "-" instead of 0, and shorten long names so the columns stay lined up
    private static String dash(int n) { return n == 0 ? "-" : String.valueOf(n); }
    private static String cut(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 1) + "~"; }

    // Quote text for CSV if it contains a comma or quote
    private static String q(String s) {
        if (s.contains(",") || s.contains("\"")) return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }
}
