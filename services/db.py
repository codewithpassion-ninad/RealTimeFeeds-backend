from pymongo import MongoClient

# MongoDB connection
MONGO_URI = 'mongodb+srv://capstone:capstone@cluster0.wrleq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
client = MongoClient(MONGO_URI)
db = client.cve_database
collection = db.cve_details

# Function to fetch paginated CVE data
def get_cve_data(page, limit):
    try:
        page = int(page)  # Ensure page is an integer
        limit = int(limit)  # Ensure limit is an integer
        skip = (page - 1) * limit
        cursor = collection.find({"cve_title": {"$ne": "N/A"}}).sort("_id", -1).skip(skip).limit(limit)
        data = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
            data.append(doc)
        total_count = collection.count_documents({"cve_title": {"$ne": "N/A"}})  # Get the total count for pagination info
        return {
            "data": data, 
            "page": page, 
            "limit": limit, 
            "total_count": total_count # Include total count
        }
    except ValueError:
        return {"error": "Invalid page or limit value"}, 400  # Handle invalid input
    except Exception as e:
        return {"error": str(e)}, 500  # Handle other errors