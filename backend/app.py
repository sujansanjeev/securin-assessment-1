from flask import Flask, jsonify, request
from flask_cors import CORS
from tinydb import TinyDB, Query
import requests
from datetime import datetime, timedelta
import threading
import time
import json

app = Flask(__name__)
CORS(app)

db = TinyDB('cve_data.json')


def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def safe_str(value):
    return str(value).strip() if value else ""


def safe_iso_date(value):
    try:
        date_formats = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]
        for fmt in date_formats:
            try:
                return datetime.strptime(value, fmt).isoformat()
            except ValueError:
                continue
    except TypeError:
        pass
    return ""


def fetch_cves_from_api(start_index=0, results_per_page=2000):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()

        
        try:
            return response.json()
        except json.JSONDecodeError as e:
            print(f"Invalid JSON response: {e}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None


def extract_cvss_metrics(metrics):
    cvss_v2 = next((m for m in metrics.get("cvssMetricV2", []) if isinstance(m, dict)), None)
    cvss_v3 = next((m for m in metrics.get("cvssMetricV3", []) if isinstance(m, dict)), None)

    return {
        "v2": {
            "baseScore": safe_float(cvss_v2.get("cvssData", {}).get("baseScore")) if cvss_v2 else 0.0,
            "vectorString": safe_str(cvss_v2.get("cvssData", {}).get("vectorString")) if cvss_v2 else "",
        },
        "v3": {
            "baseScore": safe_float(cvss_v3.get("cvssData", {}).get("baseScore")) if cvss_v3 else 0.0,
            "vectorString": safe_str(cvss_v3.get("cvssData", {}).get("vectorString")) if cvss_v3 else "",
        }
    }


def validate_and_clean_data(doc):
    if not doc.get("cve_id"):
        return None

    doc["description"] = safe_str(doc.get("description"))
    doc["status"] = safe_str(doc.get("status")).lower()
    doc["published_date"] = safe_iso_date(doc.get("published_date"))
    doc["last_modified_date"] = safe_iso_date(doc.get("last_modified_date"))

    if "cvss" in doc:
        for version in ["v2", "v3"]:
            if version in doc["cvss"]:
                doc["cvss"][version]["baseScore"] = safe_float(doc["cvss"][version].get("baseScore"))
                doc["cvss"][version]["vectorString"] = safe_str(doc["cvss"][version].get("vectorString"))

    doc["cpe"] = doc.get("cpe", [])
    for cpe in doc["cpe"]:
        cpe["criteria"] = safe_str(cpe.get("criteria"))
        cpe["matchCriteriaId"] = safe_str(cpe.get("matchCriteriaId"))
        cpe["vulnerable"] = bool(cpe.get("vulnerable", False))

    return doc



def update_database():
    try:
        last_updated_file = "last_updated.txt"
        try:
            with open(last_updated_file, "r") as f:
                last_updated = f.read().strip()
        except FileNotFoundError:
            last_updated = ""

        while True:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"lastModStartDate": last_updated} if last_updated else {}

            response = requests.get(url, params=params, timeout=30)

            try:
                response.raise_for_status()
                data = response.json()
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                print(f"Error during update: {e}")
                time.sleep(60)
                continue

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("No updates available.")
                break

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                doc = {
                    "cve_id": cve_data.get("id"),
                    "identifier": cve_data.get("sourceIdentifier"),
                    "description": next(
                        (desc["value"] for desc in cve_data.get("descriptions", []) if isinstance(desc, dict) and desc.get("lang") == "en"
                    ), ""),
                    "status": cve_data.get("vulnStatus", ""),
                    "published_date": cve_data.get("published"),
                    "last_modified_date": cve_data.get("lastModified"),
                    "cvss": extract_cvss_metrics(cve_data.get("metrics", {})),
                    "cpe": [
                        {
                            "criteria": cpe_match.get("criteria"),
                            "matchCriteriaId": cpe_match.get("matchCriteriaId"),
                            "vulnerable": cpe_match.get("vulnerable", False)
                        }
                        for config in cve_data.get("configurations", [])
                        for node in config.get("nodes", [])
                        for cpe_match in node.get("cpeMatch", [])
                    ]
                }

                cleaned_doc = validate_and_clean_data(doc)
                if cleaned_doc:
                    query = Query()
                    db.upsert(cleaned_doc, query.cve_id == cleaned_doc["cve_id"])

            last_updated = datetime.now().isoformat()
            with open(last_updated_file, "w") as f:
                f.write(last_updated)

            print(f"Updated {len(vulnerabilities)} records.")
            time.sleep(60)

    except Exception as e:
        print(f"Error in update process: {e}")


@app.route('/api/cves', methods=['GET'])
def get_cves():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    year = request.args.get('year')
    score = request.args.get('score')
    modified_days = request.args.get('modified_days')
    sort_by = request.args.get('sort_by', 'published_date')
    sort_order = request.args.get('sort_order', 'asc')

    results = db.all()

    if year:
        results = [r for r in results if r['cve_id'].split('-')[1] == year]

    if score:
        score = float(score)
        results = [r for r in results if r['cvss']['v2']['baseScore'] == score or r['cvss']['v3']['baseScore'] == score]

    if modified_days:
        cutoff_date = (datetime.now() - timedelta(days=int(modified_days))).isoformat()
        results = [r for r in results if r['last_modified_date'] >= cutoff_date]

    reverse = sort_order.lower() == 'desc'

    if sort_by in ['published_date', 'last_modified_date']:
        results = sorted(results, key=lambda x: x.get(sort_by, ''), reverse=reverse)
    else:
        results = sorted(results, key=lambda x: x.get(sort_by, ''), reverse=reverse)

    start_idx = (page - 1) * per_page
    paginated_results = results[start_idx:start_idx + per_page]

    return jsonify({
        'total_records': len(results),
        'page': page,
        'per_page': per_page,
        'results': paginated_results
    })


@app.route('/api/cves/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    query = Query()
    cve = db.search(query.cve_id == cve_id)
    if not cve:
        return jsonify({'error': 'CVE not found'}), 404
    return jsonify(cve[0])


if __name__ == '__main__':
    threading.Thread(target=update_database, daemon=True).start()
    app.run(debug=True)



