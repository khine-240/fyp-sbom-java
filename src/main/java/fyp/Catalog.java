package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

// Step 2: loads the TEAM KEV + EPSS catalog (github.com/caffeineintaker/fyp-vuln-catalog)
// after checking its fingerprints against the snapshot's manifest.json.
//   catalog.json says which snapshot to use, e.g.
//   { "catalog_dir": "vuln-catalog", "snapshot": "2026-10-29" }
public class Catalog {

    // What we keep for each CVE
    public record Epss(double score, double percentile) {}
    public record Kev(String dateAdded, String dueDate, String ransomware) {}

    public final String dir, snapshot;
    public String kevVersion = "", epssModel = "", epssScoreDate = "";
    public final Map<String, Kev> kev = new HashMap<>();
    public final Map<String, Epss> epss = new HashMap<>();
    public int kevTotal = 0, epssTotal = 0;

    private static final ObjectMapper mapper = new ObjectMapper();

    public Catalog(String configFile) throws Exception {
        JsonNode cfg = mapper.readTree(new File(configFile));
        snapshot = cfg.path("snapshot").asText();
        dir = cfg.path("catalog_dir").asText() + "/snapshots/" + snapshot;
    }

    // 1. Check kev.json and epss_scores.csv.gz against the SHA-256 in manifest.json
    public void verify() throws Exception {
        JsonNode manifest = mapper.readTree(new File(dir, "manifest.json"));
        for (String part : new String[]{"kev", "epss"}) {
            String file = manifest.path(part).path("file").asText();
            String expected = manifest.path(part).path("sha256").asText();
            if (!sha256(new File(dir, file)).equals(expected)) {
                throw new RuntimeException("Catalog file changed or damaged: " + file);
            }
            System.out.println("  " + file + ": OK");
        }
    }

    // 2. Load KEV: every CVE in the list is "known exploited"
    public void loadKev() throws Exception {
        JsonNode root = mapper.readTree(new File(dir, "kev.json"));
        kevVersion = root.path("catalogVersion").asText();
        for (JsonNode v : root.path("vulnerabilities")) {
            kev.put(v.path("cveID").asText(), new Kev(v.path("dateAdded").asText(),
                    v.path("dueDate").asText(), v.path("knownRansomwareCampaignUse").asText()));
        }
        kevTotal = kev.size();
    }

    // 3. Load EPSS, but only keep the CVEs we actually need (the file has ~397,000 lines)
    public void loadEpss(Set<String> wanted) throws Exception {
        File f = new File(dir, "epss_scores.csv.gz");
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new GZIPInputStream(new FileInputStream(f)), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#")) {                 // e.g. #model_version:v2026.06.15,score_date:2026-10-28T12:03:13Z
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

    // The day of the EPSS scores (e.g. 2026-10-28) - used to ask the API for the same day
    public String epssDay() {
        return epssScoreDate.length() >= 10 ? epssScoreDate.substring(0, 10) : epssScoreDate;
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
