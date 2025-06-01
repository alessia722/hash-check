import requests
import time
import sys
import os
import csv


from dotenv import load_dotenv
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
HA_API_KEY = os.getenv("HA_API_KEY")
HA_API_USER = os.getenv("HA_API_USER")

if not all([VT_API_KEY, HA_API_KEY, HA_API_USER]):
    raise EnvironmentError("One or more required API environment variables are missing.")

def check_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data["last_analysis_stats"]
            results = data["last_analysis_results"]

            malicious_labels = [
                res["result"]
                for res in results.values()
                if res["category"] == "malicious" and res["result"]
            ]

            unique_labels = list(set(malicious_labels))
            label_summary = ", ".join(unique_labels[:5]) # max. 5 as a preview
            if len(unique_labels) > 5:
                label_summary += ", ..."

            return (
                f"malicious: {stats.get('malicious', 0)}, "
                f"suspicious: {stats.get('suspicious', 0)}, "
                f"undetected: {stats.get('undetected', 0)}"
                f"{' | reasons: ' + label_summary if unique_labels else ''}"
            )
        elif response.status_code == 404:
            return "Not found"
        else:
            return f"Error {response.status_code}"
    except requests.Timeout:
        return "Timeout (over 10s)"
    except Exception as e:
        return f"Exception: {str(e)}"

def check_hybrid_analysis(hash_value):
    USER_AGENT = os.getenv("HA_USER_AGENT", "Mozilla/5.0 (compatible; HybridCheck/1.0; +https://example.com)")

    url = f"https://www.hybrid-analysis.com/api/v2/overview/{hash_value}"
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()

            # Verdict mit Fallback auf threat_score
            verdict = data.get("verdict")
            if not verdict or verdict.lower() == "no specific threat":
                if data.get("threat_score", 0) >= 70:
                    verdict = "malicious"
                else:
                    verdict = "unclassified"

            score = data.get("threat_score", "N/A")
            tags = data.get("classification_tags", [])
            tag_summary = ", ".join(tags[:5]) + ("..." if len(tags) > 5 else "") if tags else "No tags"

            av_detect = data.get("av_detect", "N/A")
            threat_name = data.get("threat_name", "N/A")
            indicators = data.get("total_indicators", "N/A")

            return (
                f"{verdict}, Score: {score} | "
                f"AV Detection: {av_detect} | "
                f"Threat: {threat_name} | "
                f"Indicators: {indicators} | "
                f"Reasons: {tag_summary}"
            )

        elif response.status_code == 404:
            return "Not found"
        elif response.status_code == 403:
            return "Access denied"
        elif response.status_code == 401:
            return "Invalid API key"
        else:
            return f"Error {response.status_code}"
    except requests.Timeout:
        return "Timeout (over 10s)"
    except Exception as e:
        return f"Exception: {str(e)}"

def main():
    INPUT_FILE = os.getenv("INPUT_FILE", "hashes.txt")
    OUTPUT_FILE_TXT = os.getenv("OUTPUT_TXT_FILE", "output-hash-check.txt")
    OUTPUT_FILE_CSV = os.getenv("OUTPUT_CSV_FILE", "output-hash-check.csv")
    VT_RATE_LIMIT = 4  # VirusTotal Free License: max 4 requests per minute

    try:
        with open(INPUT_FILE, "r") as f:
            hashes = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f" Input file '{INPUT_FILE}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    total = len(hashes)
    vt_counter = 0
    vt_timer = time.time()

    try:
        with open(OUTPUT_FILE_TXT, "w", encoding="utf-8") as txt_out, \
             open(OUTPUT_FILE_CSV, "w", newline="", encoding="utf-8") as csv_out:

            csv_writer = csv.writer(csv_out)
            csv_writer.writerow([
                "hash", "vt_malicious", "vt_suspicious", "vt_undetected", "vt_reasons",
                "ha_verdict", "ha_score", "ha_av_detect", "ha_threat", "ha_indicators", "ha_reasons",
                "vt_link", "ha_link"
            ])

            for i, h in enumerate(hashes, 1):
                print(f"[{i}/{total}] Checking {h}")

                if vt_counter >= VT_RATE_LIMIT:
                    elapsed = time.time() - vt_timer
                    if elapsed < 60:
                        wait = 60 - elapsed
                        print(f"⏳ Waiting {int(wait)}s due to VT rate limit…")
                        time.sleep(wait)
                    vt_counter = 0
                    vt_timer = time.time()

                vt_result = check_virustotal(h)
                vt_counter += 1
                ha_result = check_hybrid_analysis(h)

                vt_section = ""
                ha_section = ""
                vt_link = ""
                ha_link = ""

                # Parse VT
                if vt_result.lower().startswith("not found") or vt_result.lower().startswith("error"):
                    vt_section = f"VirusTotal: not found on platform.\n"
                    vt_row = ["Not found"] * 4
                else:
                    vt_parts = vt_result.split(" | reasons: ")
                    vt_stats = vt_parts[0]
                    vt_reasons = vt_parts[1] if len(vt_parts) > 1 else ""
                    malicious = suspicious = undetected = ""

                    for part in vt_stats.split(","):
                        if "malicious" in part:
                            malicious = part.split(":", 1)[1].strip()
                        elif "suspicious" in part:
                            suspicious = part.split(":", 1)[1].strip()
                        elif "undetected" in part:
                            undetected = part.split(":", 1)[1].strip()

                    vt_link = f"https://www.virustotal.com/gui/file/{h}"
                    vt_section = (
                        f"VirusTotal:\n"
                        f"{'  - malicious: ' + malicious if malicious else ''}\n"
                        f"{'  - suspicious: ' + suspicious if suspicious else ''}\n"
                        f"{'  - undetected: ' + undetected if undetected else ''}\n"
                        f"{'  - reasons: ' + vt_reasons if vt_reasons else ''}\n"
                        f"{'  - link: ' + vt_link}\n"
                    )
                    vt_row = [malicious, suspicious, undetected, vt_reasons]

                # Parse HA
                if ha_result.lower().startswith("not found") or ha_result.lower().startswith("error"):
                    ha_section = f"HybridAnalysis: not found on platform.\n"
                    ha_row = ["Not found"] * 6
                else:
                    ha_verdict = ha_score = ha_av = ha_threat = ha_indicators = ha_reasons = ""
                    try:
                        parts = ha_result.split(" | ")
                        for part in parts:
                            if part.startswith("malicious") or part.startswith("unclassified"):
                                verdict_score = part.split(", Score:")
                                ha_verdict = verdict_score[0].strip()
                                ha_score = verdict_score[1].strip() if len(verdict_score) > 1 else ""
                            elif part.startswith("AV Detection:"):
                                ha_av = part.split(":", 1)[1].strip()
                            elif part.startswith("Threat:"):
                                ha_threat = part.split(":", 1)[1].strip()
                            elif part.startswith("Indicators:"):
                                ha_indicators = part.split(":", 1)[1].strip()
                            elif part.startswith("Reasons:"):
                                ha_reasons = part.split(":", 1)[1].strip()
                    except Exception:
                        pass

                    ha_link = f"https://www.hybrid-analysis.com/sample/{h}"
                    ha_section = (
                        f"HybridAnalysis:\n"
                        f"{'  - verdict: ' + ha_verdict if ha_verdict else ''}\n"
                        f"{'  - score: ' + ha_score if ha_score else ''}\n"
                        f"{'  - AV Detection: ' + ha_av if ha_av else ''}\n"
                        f"{'  - Threat: ' + ha_threat if ha_threat else ''}\n"
                        f"{'  - Indicators: ' + ha_indicators if ha_indicators else ''}\n"
                        f"{'  - reasons: ' + ha_reasons if ha_reasons else ''}\n"
                        f"{'  - link: ' + ha_link}\n"
                    )
                    ha_row = [ha_verdict, ha_score, ha_av, ha_threat, ha_indicators, ha_reasons]

                # Write TXT
                txt_line = (
                    f"Hash: {h}\n"
                    f"{vt_section}"
                    f"{ha_section}"
                    f"{'-'*80}\n"
                )
                print(f"➡ Writing results for {h}")
                txt_out.write(txt_line)

                # Write CSV
                csv_writer.writerow([
                    h, *vt_row, *ha_row, vt_link, ha_link
                ])

    except Exception as e:
        print(f"Error writing output files: {e}")
        sys.exit(1)

    print(f"\nText output saved to: {OUTPUT_FILE_TXT}")
    print(f"CSV output saved to: {OUTPUT_FILE_CSV}")

if __name__ == "__main__":
    main()