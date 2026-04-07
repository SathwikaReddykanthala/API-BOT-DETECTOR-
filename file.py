import streamlit as st
import pandas as pd
import numpy as np
import joblib
import random
from collections import Counter

# ===============================
# Load Model and Encoder
# ===============================
model = joblib.load("rfmodel.pkl")
ohe = joblib.load("ohe.pkl")

# ===============================
# Page Config
# ===============================
st.set_page_config(page_title="Bot & Human API Traffic Analyzer", layout="wide")
st.title("🛡️ Bot & Human API Traffic Analyzer")

st.write("""
This system automatically predicts whether an API request is coming from a **Bot or Human**
based on behavioral metrics and metadata.
""")

# ===============================
# Generate Automatic API Request
# ===============================
def generate_auto_request():

    http_methods = ["get", "post", "put", "delete", "patch"]
    endpoints = [
        "/api/login",
        "/api/cart",
        "/api/products",
        "/api/search",
        "/api/orders",
        "/api/profile",
        "/api/payment"
    ]

    return {
        "http_method": random.choice(http_methods),
        "endpoint": random.choice(endpoints),
        "status_code": random.choice([200, 201, 403, 400, 401, 429, 404, 500]),
        "response_size": random.randint(200, 5000),
        "session_duration": random.randint(10, 1000),
        "requests_per_session": random.randint(1, 300),
        "time_between_requests": round(random.uniform(0.1, 30), 2),
        "failed_requests": random.randint(0, 15),
        "url_length": random.randint(20, 150),
        "query_param_count": random.randint(0, 10),
        "payload_size": random.randint(100, 20000),
        "distinct_endpoints_accessed": random.randint(1, 20),
        "login_attempts": random.randint(0, 20)
    }

auto_data = generate_auto_request()

# ===============================
# Display Incoming Request
# ===============================
st.subheader("📡 Incoming API Request")

st.write(auto_data)

http_method = auto_data["http_method"]
endpoint = auto_data["endpoint"]
status_code = auto_data["status_code"]
response_size = auto_data["response_size"]
session_duration = auto_data["session_duration"]
requests_per_session = auto_data["requests_per_session"]
time_between_requests = auto_data["time_between_requests"]
failed_requests = auto_data["failed_requests"]
url_length = auto_data["url_length"]
query_param_count = auto_data["query_param_count"]
payload_size = auto_data["payload_size"]
distinct_endpoints_accessed = auto_data["distinct_endpoints_accessed"]
login_attempts = auto_data["login_attempts"]

def calculate_entropy(requests):
    counts = Counter(requests)
    probabilities = [count / len(requests) for count in counts.values()]
    entropy = -sum(p * np.log2(p) for p in probabilities)
    return entropy

request_list = [
    http_method,
    endpoint,
    status_code,
    response_size,
    session_duration,
    requests_per_session,
    time_between_requests,
    failed_requests,
    url_length,
    query_param_count,
    payload_size,
    distinct_endpoints_accessed
]

request_pattern_entropy = calculate_entropy(request_list)

# ===============================
# Threat Detection Logic
# ===============================
def detect_threat(bot_prob, failed_requests, login_attempts,
                  requests_per_session, time_between_requests,
                  distinct_endpoints_accessed, session_duration):

    if bot_prob >= 80:
        return "🚨 Critical Bot Activity", "Possible Automated Attack", "Block Request (403)"

    elif bot_prob >= 40:

        if login_attempts > 10 or failed_requests > 8:
            return "⚠️ Brute Force Attack", "Multiple login attempts detected", "Apply CAPTCHA / Temporary Block"

        elif requests_per_session > 50 or distinct_endpoints_accessed > 6:
            return "⚠️ Data Scraping Activity", "Large number of requests detected", "Apply Rate Limiting"

        elif time_between_requests < 0.5 or session_duration <= 30:
            return "⚠️ High Frequency Bot", "Requests sent too quickly", "Throttle Traffic"

        else:
            return "⚠️ Suspicious Bot Activity", "Unusual request behavior", "Monitor Closely"

    else:
        return "🟢 Normal Traffic", "No suspicious activity", "Allow Request"

# ===============================
# Prepare Data for Prediction
# ===============================
row = pd.DataFrame([[

    http_method,
    endpoint,
    status_code,
    response_size,
    session_duration,
    requests_per_session,
    time_between_requests,
    failed_requests,
    url_length,
    query_param_count,
    payload_size,
    distinct_endpoints_accessed,
    login_attempts,
    request_pattern_entropy

]], columns=[

    "http_method",
    "endpoint",
    "status_code",
    "response_size",
    "session_duration",
    "requests_per_session",
    "time_between_requests",
    "failed_requests",
    "url_length",
    "query_param_count",
    "payload_size",
    "distinct_endpoints_accessed",
    "login_attempts",
    "request_pattern_entropy"

])

# ===============================
# Encode Categorical Data
# ===============================
cat_cols = ["http_method", "endpoint"]

encoded = ohe.transform(row[cat_cols])

if hasattr(encoded, "toarray"):
    encoded = encoded.toarray()

encoded_df = pd.DataFrame(encoded, columns=ohe.get_feature_names_out())

row_final = row.drop(cat_cols, axis=1)
row_final = pd.concat([row_final.reset_index(drop=True), encoded_df], axis=1)

# ===============================
# Model Prediction
# ===============================
pred = model.predict(row_final)[0]
prob = model.predict_proba(row_final)[0]

bot_prob = prob[1] * 100
human_prob = prob[0] * 100

# ===============================
# Threat Detection
# ===============================
threat_level, threat_reason, action = detect_threat(
    bot_prob,
    failed_requests,
    login_attempts,
    requests_per_session,
    time_between_requests,
    distinct_endpoints_accessed,
    session_duration
)

# ===============================
# Classification Threshold
# ===============================
threshold = 80

if bot_prob >= threshold:
    label = "BOT"
    confidence = bot_prob
    st.error("⚠️ BOT DETECTED")

else:
    label = "HUMAN"
    confidence = human_prob
    st.success("✅ HUMAN TRAFFIC")

# ===============================
# Display Prediction
# ===============================
st.subheader(f"🔍 Prediction: {label}")
st.write(f"Confidence: {confidence:.2f}%")

# ===============================
# Threat Analysis
# ===============================
st.subheader("🛡️ Threat Analysis")

if "Critical" in threat_level:
    st.error(threat_level)

elif "⚠️" in threat_level:
    st.warning(threat_level)

elif "🟢" in threat_level:
    st.info(threat_level)

else:
    st.success(threat_level)

st.write(f"Reason: **{threat_reason}**")
st.write(f"Recommended Action: **{action}**")

# ===============================
# Explain Confidence
# ===============================
with st.expander("How Confidence is Calculated?"):

    st.markdown(f"- Model predicted probabilities: HUMAN = {human_prob:.2f}%, BOT = {bot_prob:.2f}%")
    st.markdown(f"- Threshold for BOT detection: {threshold}%")
    st.markdown(f"- Predicted class probability = {confidence:.2f}% → this value is shown as Confidence")
    st.markdown("- Confidence is based on the probability output from the ML model.")







    
    
    
