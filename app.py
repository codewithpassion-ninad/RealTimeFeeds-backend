from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from services.db import get_cve_data
from services.scraper import fetch_cve_data, classify_attack_type_enhanced, notify_subscribers
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import threading
import time

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

MONGO_URI = 'mongodb+srv://capstone:capstone@cluster0.wrleq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
client = MongoClient(MONGO_URI, server_api=ServerApi('1'))

cve_db = client.cve_database
cve_collection = cve_db.cve_details

user_db = client.user_db
user_collection = user_db.user_details
user_queries = user_db.user_queries
subscribers_collection = user_db.subscribers

# User Registration
@app.route('/api/v1/auth/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    existing_user = user_collection.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = generate_password_hash(password)
    user_collection.insert_one({'username': username, 'password': hashed_password})

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/v1/auth/login', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = user_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    if not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid username or password'}), 401

    return jsonify({'message': 'Login successful'}), 200

@app.route('/api/v1/cve/data', methods=['GET'])
def get_incidents():
    page = request.args.get('page', 1)  # Get page number from query parameters (default 1)
    limit = request.args.get('limit', 12)  # Get limit from query parameters (default 12)
    result = get_cve_data(page, limit)

    if "error" in result:  # Check for errors from get_cve_data
        return jsonify(result), result.get("error", 500)  # Return error and status code

    return jsonify(result)  # Return the data

@app.route('/api/v1/cve/details/<cve_id>', methods=['GET'])
def get_incident(cve_id):
    cve = cve_collection.find_one({'cve_id': str(cve_id)})
    if not cve:
        return jsonify({'error': 'CVE not found'}), 404

    # Ensure all necessary fields are included in the response
    response = {
        'cve_id': cve.get('cve_id'),
        'cve_title': cve.get('cve_title', 'N/A'),
        'cve_description': cve.get('cve_description', 'N/A'),
        'cvss_score': cve.get('cvss_score', 'N/A'),
        'base_severity': cve.get('base_severity', 'N/A'),
        'published_date': cve.get('published_date', 'N/A'),
        'updated_date': cve.get('updated_date', 'N/A'),
        'references': cve.get('references', []),
        'attack_type': cve.get('attack_type', 'N/A')
    }

    return jsonify(response)

@app.route('/api/v1/cve/visualize', methods=['GET'])
def get_cve_details():
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    attack_type = request.args.get("attack_type", "all")

    if not start_date or not end_date:
        return jsonify({'error': 'Start date and end date are required'}), 400

    query = {"updated_date": {"$gte": start_date, "$lte": end_date}}
    if attack_type != "all":
        query["attack_type"] = attack_type

    data = list(cve_collection.find(query, {"_id": 0, "cvss_score": 1, "attack_type": 1, "updated_date": 1}))

    return jsonify(data)

@app.route('/api/v1/contact', methods=['POST'])
def contact_us():
    data = request.json
    full_name = data.get('full_name')
    email = data.get('email')
    query = data.get('message')

    if not full_name or not email or not query:
        return jsonify({'error': 'All fields are required'}), 400

    user_queries.insert_one({'full_name': full_name, 'email': email, 'query': query})
    return jsonify({'message': 'Query submitted successfully'}), 200

@app.route("/api/incidents/latest", methods=["GET"])
def get_latest_incidents():
    latest_incidents = cve_collection.find().sort("updated_date", -1).limit(10)
    incidents_list = []
    for incident in latest_incidents:
        cve_id = incident.get('cve_id')
        cve_title = incident.get('cve_title', 'N/A')
        if cve_id == 'N/A' or cve_title == 'N/A':
            continue
        incidents_list.append({
            'cve_id': cve_id,
            'cve_title': cve_title,
            'cve_description': incident.get('cve_description', 'N/A'),
            'cvss_score': incident.get('cvss_score', 'N/A'),
            'base_severity': incident.get('base_severity', 'N/A'),
            'published_date': incident.get('published_date', 'N/A'),
            'updated_date': incident.get('updated_date', 'N/A'),
            'references': incident.get('references', []),
            'attack_type': incident.get('attack_type', 'N/A')
        })
        if len(incidents_list) >= 5:
            break
    return jsonify(incidents_list), 200

@app.route("/api/v1/subscribe", methods=["POST"])
def subscribe():
    data = request.json
    email = data.get("email")
    phone = data.get("phone")

    if not email and not phone:
        return jsonify({"error": "At least one contact method required"}), 400

    subscribers_collection.insert_one(
        {"email": email, "phone": phone, "created_at": datetime.utcnow()}
    )

    return jsonify({"message": "Subscription successful"}), 201


@app.route('/api/v1/settings/change-password', methods=['PUT'])
def change_password():
    data = request.json
    print(data)
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not username or not old_password or not new_password:
        return jsonify({'error': 'All fields are required'}), 400

    user = user_collection.find_one({'username': username})
    if not user or not check_password_hash(user['password'], old_password):
        return jsonify({'error': 'Invalid username or old password'}), 401

    hashed_new_password = generate_password_hash(new_password)
    user_collection.update_one({'username': username}, {'$set': {'password': hashed_new_password}})

    return jsonify({'message': 'Password changed successfully'}), 200

# Update Profile (Email, Full Name)
@app.route('/api/v1/settings/update-profile', methods=['PUT'])
def update_profile():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    full_name = data.get('full_name')

    if not username or not email or not full_name:
        return jsonify({'error': 'All fields are required'}), 400

    user_collection.update_one({'username': username}, {'$set': {'email': email, 'full_name': full_name}})
    return jsonify({'message': 'Profile updated successfully'}), 200

# Update Preferences (Notifications)
@app.route('/api/v1/settings/update-preferences', methods=['PUT'])
def update_preferences():
    data = request.json
    username = data.get('username')
    notifications_enabled = data.get('notifications_enabled', True)

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    user_collection.update_one({'username': username}, {'$set': {'notifications_enabled': notifications_enabled}})
    return jsonify({'message': 'Preferences updated successfully'}), 200

def scrape_continuously():
    scrape()
    while True:
        try:
            scrape()
        except Exception as e:
            print(f"Error during scraping: {e}")
        time.sleep(3600)

@app.route("/api/v1/scrape", methods=["POST"])
def scrape():
    urls = [
        "https://www.nciipc.gov.in/alert_and_advisories.html"
    ]
    all_data = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    for url in urls:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        advisories_section = soup.find_all("li", class_="liList")

        if not advisories_section:
            print(f"Could not find advisories section on {url}. Please check the class name or structure.")
            continue

        # Step 6: Extract details into a structured format
        for advisory in advisories_section:
            title_date = advisory.get_text(strip=True).split(")", 1)
            title_with_date = title_date[0] if title_date else "N/A"

            # Extract title
            title = title_with_date.rsplit("(", 1)[0].strip() if "(" in title_with_date else title_with_date.strip()

            # Extract date
            date = title_with_date.rsplit("(", 1)[1].strip() if "(" in title_with_date else "N/A"

            # Extract description (text after the date and before CVE ID)
            description = title_date[1].split("CVE ID:", 1)[0].strip() if len(title_date) > 1 else "N/A"

            # Extract CVE ID
            cve_id = title_date[1].split("CVE ID:", 1)[1].strip() if "CVE ID:" in title_date[1] else "N/A"

            if cve_id != "N/A":
                all_data.append({
                    "cve_id": cve_id,
                    "title": title,
                    "description": description
                })

    for item in all_data:
        cve_id = item['cve_id']
        cve_id = cve_id.split(" ")[0]
        cve_data = fetch_cve_data(cve_id)
        if cve_data:
            try:
                existing_cve = cve_collection.find_one({"cve_id": cve_id})
                if existing_cve:
                    print(f"CVE ID {cve_id} already exists in the database. Skipping.")
                    continue

                metadata = cve_data.get("cveMetadata", {})
                containers = cve_data.get("containers", {}).get("cna", {})
                cve_title = containers.get("title", "N/A")
                cve_description = containers.get("descriptions", [{}])[0].get("value", "N/A")
                # summary = generate_summary(cve_description)
                cvss_data = containers.get("metrics", [{}])[0].get("cvssV3_1", {})
                cvss_score = cvss_data.get("baseScore", "N/A")
                base_severity = cvss_data.get("baseSeverity", "N/A")
                published_date = metadata.get("datePublished", "N/A")
                updated_date = metadata.get("dateUpdated", "N/A")
                references = "; ".join([ref.get("url", "N/A") for ref in containers.get("references", [])])

                # Classify attack type
                attack_type = classify_attack_type_enhanced(cve_description)
                print(f"Attack type for CVE ID {cve_id}: {attack_type}")
                # Insert data into MongoDB
                latest_cve = cve_collection.find_one(sort=[("_id", -1)])
                next_id = latest_cve["_id"] + 1 if latest_cve else 1
                print(next_id)
                cve_details = {
                    "_id": next_id,
                    "cve_id": cve_id,
                    "cve_title": cve_title,
                    "cve_description": cve_description,
                    # "summary": summary,
                    "cvss_score": cvss_score,
                    "base_severity": base_severity,
                    "published_date": published_date,
                    "updated_date": updated_date,
                    "references": references,
                    "attack_type": attack_type
                }
                cve_collection.insert_one(cve_details)
                print(f"Inserted data for CVE ID {cve_id} into MongoDB.")    
                if not existing_cve and not existing_cve.get("notified", False):
                    notify_subscribers(cve_details)
                    cve_collection.update_one({"cve_id": cve_id}, {"$set": {"notified": True}})

            except Exception as e:
                print(f"Error processing CVE ID {cve_id}: {e}")
        else:
            print(f"Could not fetch data for CVE ID {cve_id}")

# Start the continuous scraping in a separate thread
scraping_thread = threading.Thread(target=scrape_continuously)
scraping_thread.daemon = True
scraping_thread.start()

if __name__ == '__main__':
    socketio.run(app, debug=True)
