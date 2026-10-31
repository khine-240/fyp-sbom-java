package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

// Step 2: loads our frozen KEV + EPSS catalog (catalog/<date>/) after checking its fingerprints.
//   catalog.json says which snapshot to use, e.g. { "catalog_dir": "catalog/2026-10-22", "epss_date": "2026-10-22" }
public class Catalog {

    // What we keep for each CVE
    public record Epss(double score, double percentile) {}
    public record Kev(String dateAdded, String ransomware, String name) {}

    public final String dir, epssDate;
    public String kevVersion = "", epssModel = "", epssScoreDate = "";
    public final Map<String, Kev> kev = new HashMap<>();
    public final Map<String, Epss> epss = new HashMap<>();
    public int kevTotal = 0, epssTotal = 0;

    private static final ObjectMapper mapper = new ObjectMapper();

    public Catalog(String configFile) throws Exception {
        JsonNode cfg = mapper.readTree(new File(configFile));
        dir = cfg.path("catalog_dir").asText();
        epssDate = cfg.path("epss_date").asText();
    }

    // 1. Check every file against SHA256SUMS, so we know the catalog was not changed
    public void verify() throws Exception {
        List<String> lines = Files.readAllLines(new File(dir, "SHA256SUMS").toPath());
        for (String line : lines) {
            if (line.isBlank()) continue;
            String expected = line.substring(0, 64);
            String path = line.substring(64).trim();
            String actual = sha256(new File(dir, path));
            if (!actual.equals(expected)) {
                throw new RuntimeException("Catalog file changed or damaged: " + path);
            }
            System.out.println("  " + path + ": OK");
        }
    }

    // 2. Load KEV: every CVE in the list is "known exploited"
    public void loadKev() throws Exception {
        JsonNode root = mapper.readTree(new File(dir, "kev/known_exploited_vulnerabilities.json"));
        kevVersion = root.path("catalogVersion").asText();
        for (JsonNode v : root.path("vulnerabilities")) {
            kev.put(v.path("cveID").asText(), new Kev(v.path("dateAdded").asText(),
                    v.path("knownRansomwareCampaignUse").asText(), v.path("vulnerabilityName").asText()));
        }
        kevTotal = kev.size();
    }

    // 3. Load EPSS, but only keep the CVEs we actually need (the file has ~394,000 lines)
    public void loadEpss(Set<String> wanted) throws Exception {
        File f = new File(dir, "epss/epss_scores-" + epssDate + ".csv.gz");
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new GZIPInputStream(new FileInputStream(f)), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#")) {                 // e.g. #model_version:v2026.06.15,score_date:2026-10-22T12:00:12Z
                    for (String part : line.substring(1).split(",")) {
                        if (part.startsWith("model_version:")) epssModel = part.substring(14);
                        if (part.startsWith("score_date:")) epssScoreDate = part.substring(11);
                    }
                    continue;
                }
                if (line.startsWith("cve,")) continue;      // header line
                epssTotal++;
                String[] p = line.split(",");
                if (p.length >= 3 && wanted.contains(p[0])) {
                    epss.put(p[0], new Epss(Double.parseDouble(p[1]), Double.parseDouble(p[2])));
                }
            }
        }
    }

    static String sha256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
