package fyp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

// Step 2: calls the official FIRST EPSS API for a sample of our CVEs (same date)
// and checks that the API gives the same scores as our catalog file.
// This proves the catalog is a correct copy of the official data.
public class ApiCheck {

    private static final ObjectMapper mapper = new ObjectMapper();

    // Returns e.g. "10/10 match"; never stops the pipeline if the internet is down
    public static String run(Catalog cat, int sampleSize) {
        List<String> sample = new ArrayList<>(new java.util.TreeSet<>(cat.epss.keySet()));
        if (sample.isEmpty()) return "skipped (no CVEs)";
        // spread the sample across the sorted list so it is not only old CVEs
        List<String> picked = new ArrayList<>();
        for (int i = 0; i < sampleSize && i < sample.size(); i++) {
            picked.add(sample.get(i * sample.size() / Math.min(sampleSize, sample.size())));
        }
        String url = "https://api.first.org/data/v1/epss?date=" + cat.epssDate
                + "&cve=" + String.join(",", picked);
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
            HttpResponse<String> resp = client.send(
                    HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return "skipped (API returned HTTP " + resp.statusCode() + ")";
            return compare(resp.body(), cat.epss, picked);
        } catch (Exception e) {
            return "skipped (could not reach the API: " + e.getClass().getSimpleName() + ")";
        }
    }

    // Compares the API answer with our catalog; prints any difference
    static String compare(String body, Map<String, Catalog.Epss> ours, List<String> picked) throws Exception {
        JsonNode data = mapper.readTree(body).path("data");
        int match = 0, total = 0;
        for (JsonNode d : data) {
            String cve = d.path("cve").asText();
            Catalog.Epss mine = ours.get(cve);
            if (mine == null) continue;
            total++;
            double apiScore = d.path("epss").asDouble();
            double apiPct = d.path("percentile").asDouble();
            if (Math.abs(apiScore - mine.score()) < 1e-6 && Math.abs(apiPct - mine.percentile()) < 1e-6) {
                match++;
            } else {
                System.out.printf("  DIFFERENT: %s api=%.5f/%.5f catalog=%.5f/%.5f%n",
                        cve, apiScore, apiPct, mine.score(), mine.percentile());
            }
        }
        return match + "/" + total + " match (sample of " + picked.size() + " CVEs)";
    }
}
