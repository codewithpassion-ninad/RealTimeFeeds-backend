import requests
from bs4 import BeautifulSoup
import json
from pymongo import MongoClient
import re
import numpy as np
import tensorflow as tf
from transformers import BertTokenizer, TFBertModel
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.layers import Input, Conv1D, GlobalMaxPooling1D, Bidirectional, LSTM, concatenate, Dense, Dropout
from tensorflow.keras.models import Model
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
import os

# MongoDB connection
MONGO_URI = os.getenv('MONGO_URI')
client = MongoClient(MONGO_URI)
db = client.cve_database
user_db = client.user_db
collection = db.cve_details
subscribers_collection = user_db.subscribers

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

TWILIO_SID = os.getenv('TWILIO_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE = os.getenv('TWILIO_PHONE_NUMBER')
twilio_client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')

# Load enhanced attack keywords
# with open('enhanced_attack_keywords.json', 'r') as file:
#     enhanced_attack_keywords = json.load(file)

def send_email(subject, body, to_email):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(msg["From"], [msg["To"]], msg.as_string())

def send_sms(body, to_phone):
    twilio_client.messages.create(
        body=body, from_=TWILIO_PHONE, to=to_phone
    )

def notify_subscribers(incident):
    subject = "New Cyber Incident Alert"
    body = f"A new incident has been reported: {incident['cve_id']} - {incident['cve_title']}"

    subscribers = list(subscribers_collection.find())

    for sub in subscribers:
        if sub["email"]:
            send_email(subject, body, sub["email"])
        if sub["phone"]:
            send_sms(body, sub["phone"])
    print("Notified subscribers.")

# Function to classify attack type
def classify_attack_type_enhanced(description):
    # Initialize tokenizer
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    bert_model = TFBertModel.from_pretrained('bert-base-uncased')

    class BertEmbeddingLayer(tf.keras.layers.Layer):
        def __init__(self, bert_model, **kwargs):
            super(BertEmbeddingLayer, self).__init__(**kwargs)
            self.bert = bert_model

        def call(self, inputs):
            input_ids, attention_mask = inputs
            return self.bert(input_ids, attention_mask=attention_mask)[0]  # Output embeddings

    # Encode labels
    data = pd.read_csv(os.path.join(os.path.dirname(__file__), '../Final_data_updated.csv')).drop(columns='CVE ID', axis=1)
    print(data.head(2))

    # Encode labels
    label_encoder = LabelEncoder()
    data['Attack_Type'] = label_encoder.fit_transform(data['Attack_Type'])
    n_classes = len(label_encoder.classes_)

    input_ids_layer = Input(shape=(128,), dtype=tf.int32, name='input_ids')
    attention_mask_layer = Input(shape=(128,), dtype=tf.int32, name='attention_mask')

    # Pass through BERT
    bert_embeddings = BertEmbeddingLayer(bert_model)([input_ids_layer, attention_mask_layer])

    # **First CNN Block**
    cnn_output = Conv1D(filters=128, kernel_size=3, activation='relu', padding='same')(bert_embeddings)
    cnn_output = GlobalMaxPooling1D()(cnn_output)

    # **First LSTM Block**
    lstm_output = Bidirectional(LSTM(128, return_sequences=False, dropout=0.3, recurrent_dropout=0.3))(bert_embeddings)

    # **Second CNN Block**
    cnn_output2 = Conv1D(filters=256, kernel_size=3, activation='relu', padding='same')(bert_embeddings)
    cnn_output2 = GlobalMaxPooling1D()(cnn_output2)

    # **Second LSTM Block**
    lstm_output2 = LSTM(256, return_sequences=False, dropout=0.3, recurrent_dropout=0.3)(bert_embeddings)

    # **Merge All Features**
    merged_output = concatenate([cnn_output, lstm_output, cnn_output2, lstm_output2])

    # **Fully Connected Layers**
    merged_output = Dense(512, activation='relu')(merged_output)
    merged_output = Dropout(0.2)(merged_output)

    merged_output = Dense(256, activation='relu')(merged_output)
    merged_output = Dropout(0.2)(merged_output)

    merged_output = Dense(128, activation='relu')(merged_output)
    merged_output = Dropout(0.2)(merged_output)

    # **Classification Layer**
    output_layer = Dense(n_classes, activation='softmax')(merged_output)

    model = Model(inputs=[input_ids_layer, attention_mask_layer], outputs=output_layer)
    model.compile(loss='categorical_crossentropy', optimizer=tf.keras.optimizers.Adam(), metrics=['accuracy'])

    # Prepare input data
    encoded_texts = tokenizer(
        [description], padding='max_length', truncation=True, max_length=128, return_tensors='tf'
    )
    input_ids, attention_mask = encoded_texts['input_ids'].numpy(), encoded_texts['attention_mask'].numpy()

    # Load trained model weights
    try:
        model.load_weights(os.path.join(os.path.dirname(__file__), '../enhanced2.weights.h5'))
    except Exception as e:
        print(f"Error loading model weights: {e}")
        return "Unknown"

    # Predict attack type
    predictions = model.predict([input_ids, attention_mask])
    predicted_class = np.argmax(predictions, axis=1)[0]

    attack_type = label_encoder.inverse_transform([predicted_class])[0]
    return attack_type

def fetch_cve_data(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for CVE ID {cve_id}: {e}")
        return None

# Scraping function
def scrape_cve_data():
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
                existing_cve = collection.find_one({"cve_id": cve_id})
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
                next_id = collection.count_documents({}) + 1

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
                collection.insert_one(cve_details)
                print(f"Inserted data for CVE ID {cve_id} into MongoDB.")    
                if not existing_cve or not existing_cve.get("notified", False):
                    notify_subscribers(cve_details)
                    collection.update_one({"cve_id": cve_id}, {"$set": {"notified": True}})

            except Exception as e:
                print(f"Error processing CVE ID {cve_id}: {e}")
        else:
            print(f"Could not fetch data for CVE ID {cve_id}")


print(classify_attack_type_enhanced("A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the System user."))