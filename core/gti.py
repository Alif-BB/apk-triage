import vt
from core.analyser import DANGEROUS_PERMISSIONS


def check_virustotal(filepath, result, api_key):
    """
    Queries VirusTotal / GTI for APK hash, IP, and URL reputation.
    Returns a gti dict: { file, ips, urls, errors }
    """
    gti = {"file": None, "ips": {}, "urls": {}, "errors": []}

    try:
        with vt.Client(api_key) as client:

            # 1 ── APK file hash
            try:
                file_report = client.get_object(f"/files/{result['sha256']}")
                stats = file_report.last_analysis_stats
                gti["file"] = {
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "undetected":  stats.get("undetected", 0),
                    "total":       sum(stats.values()),
                    "tags":        getattr(file_report, "tags", []),
                    "threat_name": getattr(file_report, "popular_threat_classification", {})
                                    .get("suggested_threat_label", "Unknown"),
                    "first_seen":  str(getattr(file_report, "first_submission_date", "N/A")),
                    "times_seen":  getattr(file_report, "times_submitted", 0),
                    "link":        f"https://www.virustotal.com/gui/file/{result['sha256']}"
                }
            except vt.error.APIError as e:
                if "NotFoundError" in str(e):
                    gti["file"] = {"not_found": True}
                else:
                    gti["errors"].append(f"File lookup failed: {e}")

            # 2 ── IP reputation
            for ip in list(result["ips"])[:10]:
                try:
                    ip_report = client.get_object(f"/ip_addresses/{ip}")
                    stats = ip_report.last_analysis_stats
                    gti["ips"][ip] = {
                        "malicious": stats.get("malicious", 0),
                        "total":     sum(stats.values()),
                        "country":   getattr(ip_report, "country", "Unknown"),
                        "owner":     getattr(ip_report, "as_owner", "Unknown"),
                        "link":      f"https://www.virustotal.com/gui/ip-address/{ip}"
                    }
                except vt.error.APIError:
                    gti["ips"][ip] = None

            # 3 ── URL reputation
            for url in list(result["urls"])[:5]:
                try:
                    url_id = vt.url_id(url)
                    url_report = client.get_object(f"/urls/{url_id}")
                    stats = url_report.last_analysis_stats
                    gti["urls"][url] = {
                        "malicious": stats.get("malicious", 0),
                        "total":     sum(stats.values()),
                        "link":      f"https://www.virustotal.com/gui/url/{url_id}"
                    }
                except vt.error.APIError:
                    gti["urls"][url] = None

    except Exception as e:
        gti["errors"].append(f"GTI connection error: {str(e)}")

    return gti


def gti_score_boost(gti):
    """Returns extra risk score points based on GTI confirmation."""
    boost = 0
    if gti.get("file") and not gti["file"].get("not_found"):
        malicious = gti["file"].get("malicious", 0)
        if malicious > 20:
            boost += 50
        elif malicious > 5:
            boost += 30
        elif malicious > 0:
            boost += 15
    for ip, data in gti.get("ips", {}).items():
        if data and data.get("malicious", 0) > 0:
            boost += 20
    for url, data in gti.get("urls", {}).items():
        if data and data.get("malicious", 0) > 0:
            boost += 10
    return boost