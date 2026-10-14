# Sentinel-Z: submission explainer

**Team Bitverse · IBM Z Datathon 2026 · Challenge 2: AI Secured – Innovation Without Exposure**

## The problem

Banks need AI to spot account takeovers, mule transfers and data theft quickly. But the logs that reveal those attacks are full of personal data. Shipping them to an external AI service, or even handing them to a wide analytics team, creates a new exposure. The question in this challenge is how to get the benefit of AI without that exposure.

## Our answer in one line

Bring the AI to the data, and take identity out of the data before the AI sees it.

## What we built

Sentinel-Z is a zero-dependency anomaly detection engine for banking security logs, with a dashboard and a command-line tool.

1. **Privacy first.** Every identifier is replaced by a keyed HMAC-SHA256 pseudonym. Personal data in free text (emails, phone numbers, cards checked with Luhn, Aadhaar, PAN, IPs) is masked. Statistics shared outside the security team carry differential-privacy noise (ε = 1).
2. **Learns normal per customer.** It needs no labelled attacks: it learns from history.
3. **Hybrid detection.** An Isolation Forest, written from scratch, finds the unusual. Expert rules add evidence for known attack patterns. Each part covers the other's blind spots, and our ablation shows this.
4. **Explains every alert** in plain English and groups alerts into incidents an analyst can act on.
5. **Supports the analyst**: incident triage with notes, MITRE ATT&CK mapping, a per-customer risk timeline, a what-if threshold slider and a printable report.
6. **Red-teams itself**: a built-in simulator injects seven kinds of attack into the synthetic bank and shows live whether each is caught. The subtle insider case is sometimes missed, and we show that openly.
7. **Runs where the data lives**, on Linux on IBM Z / LinuxONE (s390x), with a container built for s390x in CI. An optional analyst summary comes from IBM Granite running locally.

## Evidence

The synthetic bank has 80 customers over 21 days and 26 injected attacks of 7 types.

- ROC-AUC 0.998, recall 94.2%, precision 78.5%, false-alarm rate 1.55%.
- All 26 attacks caught. The result holds on seeds 7, 11 and 23.
- Hybrid recall is 94.2%, against 67.5% for the model alone and 85.0% for the rules alone.
- The insider-misuse attack has no rule. The model catches 15 of its 20 events; the rules catch 6.
- The dashboard shows **0 requests to other servers**, and a Content-Security-Policy makes uploads impossible.
- 15 automated tests. They include checks that no raw email or internal IP appears anywhere in the output.

## Why IBM Z

Core banking already runs on IBM Z. An engine with no dependencies, no GPU requirement and no cloud calls can run on the same platform as the data. It inherits the platform's security and the data never has to move. The Isolation Forest inference path is a natural fit for the IBM Z Integrated Accelerator for AI as volumes grow.

## Honest limits

- The data is synthetic.
- Baselines are static per run.
- Geolocation is city-level only.

Next steps: validate on real or public logs, add rolling baselines and analyst feedback, and add streaming ingestion.

## Try it

- Live: see the README for the deployed URL. Press **Run demo scenario**.
- Local: `git clone https://github.com/sangralrahul/sentinel-z && cd sentinel-z && npm test && npm start`
