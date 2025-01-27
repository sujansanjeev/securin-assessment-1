from flask import Flask, jsonify, request
from flask_cors import CORS
from tinydb import TinyDB, Query
import requests
from datetime import datetime, timedelta
import threading
import time

app = Flask(__name__)
CORS(app)


db = TinyDB('cve_data.json')

def fetch_cves_from_api(start_index=0, results_per_page=2000):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return None

def parse_date(date_str):
    if not date_str:
        return None
    date_formats = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]
    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt).isoformat()
        except ValueError:
            continue
    return None

def extract_cvss_metrics(metrics):
    if not metrics:
        return {}
    
    cvss_v2 = next((m for m in metrics.get("cvssMetricV2", []) if isinstance(m, dict) and m.get("cvssData", {}).get("version") == "2.0"), None)
    cvss_v3 = next((m for m in metrics.get("cvssMetricV3", []) if isinstance(m, dict) and m.get("cvssData", {}).get("version", "").startswith("3")), None)
    
    return {
        "v2": {
            "baseScore": cvss_v2.get("cvssData", {}).get("baseScore") if cvss_v2 else None,
            "vectorString": cvss_v2.get("cvssData", {}).get("vectorString") if cvss_v2 else None,
        },
        "v3": {
            "baseScore": cvss_v3.get("cvssData", {}).get("baseScore") if cvss_v3 else None,
            "vectorString": cvss_v3.get("cvssData", {}).get("vectorString") if cvss_v3 else None,
        }
    }


def update_database():
    while True:
        try:
            total_results = 0
            start_index = 0
            
            while True:
                data = fetch_cves_from_api(start_index)
                if not data:
                    break
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                
                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    
                    cve_id = cve_data.get("id")
                    published = cve_data.get("published")
                    last_modified = cve_data.get("lastModified")
                    metrics = cve_data.get("metrics", [])
                    source_identifier = cve_data.get("sourceIdentifier")

                    
                    cvss_data = extract_cvss_metrics(metrics)
                    
                    # Convert dates
                    published_date = parse_date(published)
                    last_modified_date = parse_date(last_modified)
                    
                    # Prepare CPE data
                    cpe_data = []
                    for config in cve_data.get("configurations", []):
                        for node in config.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                cpe_data.append({
                                    "criteria": cpe_match.get("criteria"),
                                    "matchCriteriaId": cpe_match.get("matchCriteriaId"),
                                    "vulnerable": cpe_match.get("vulnerable", False)
                                })
                    
                    # Prepare document for insertion/update
                    doc = {
                        "cve_id": cve_id,
                        "identifier": source_identifier,
                        "description": next((desc["value"] for desc in cve_data.get("descriptions", []) if isinstance(desc, dict) and desc.get("lang") == "en"), ""),
                        "status": cve_data.get("vulnStatus", ""),
                        "published_date": published_date,
                        "last_modified_date": last_modified_date,
                        "cvss": cvss_data,
                        "cpe": cpe_data
                    }
                    
                    # Update or insert
                    query = Query()
                    db.upsert(doc, query.cve_id == cve_id)
                
                start_index += len(vulnerabilities)
                total_results += len(vulnerabilities)
                
                if total_results >= data.get("totalResults", 0):
                    break
                
        except Exception as e:
            print(f"Error in update process: {e}")
        
        
        time.sleep(24 * 60 * 60)

@app.route('/api/cves', methods=['GET'])
def get_cves():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    year = request.args.get('year')
    score = request.args.get('score')
    modified_days = request.args.get('modified_days')
    sort_by = request.args.get('sort_by')
    sort_order = request.args.get('sort_order', 'asc')
    
    query = Query()
    results = db.all()
    
    
    if year:
        results = [r for r in results if r['cve_id'].split('-')[1] == year]
    
    if score:
        score = float(score)
        results = [r for r in results if r['cvss']['v2']['baseScore'] == score or r['cvss']['v3']['baseScore'] == score]
    
    if modified_days:
        days = int(modified_days)
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        results = [r for r in results if r['last_modified_date'] >= cutoff_date]
    
    
    if sort_by:
        reverse = sort_order.lower() == 'desc'
        results = sorted(results, key=lambda x: x.get(sort_by, ''), reverse=reverse)
    
    
    total_records = len(results)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_results = results[start_idx:end_idx]
    
    return jsonify({
        'total_records': total_records,
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
    update_thread = threading.Thread(target=update_database, daemon=True)
    update_thread.start()
    app.run(debug=True)
