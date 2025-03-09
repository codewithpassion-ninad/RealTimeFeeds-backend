from flask import Blueprint, request, jsonify
from services.scraper import scrape_cve_data
from services.db import get_cve_data

cve_blueprint = Blueprint("cve", __name__)

# API to trigger scraping
@cve_blueprint.route("/scrape", methods=["POST"])
def trigger_scraping():
    try:
        scrape_cve_data()
        return jsonify({"message": "Scraping triggered successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API to fetch paginated data
@cve_blueprint.route("/data", methods=["GET"])
def fetch_data():
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 10))
        data = get_cve_data(page, limit)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500