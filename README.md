Bot & Human API Traffic Analyzer

A Machine Learning-powered web application that detects whether incoming API traffic is from a Bot or Human, and provides threat analysis with recommended actions.

Features
>> Real-time Bot vs Human prediction
>> Automatic API request simulation
>> Behavioral feature analysis
>> ML model using Random Forest
>> Threat detection (Brute Force, Scraping, etc.)
>> Action recommendations (Block, CAPTCHA, Rate Limit)
>> Confidence score explanation

How It Works
>> A simulated API request is generated with random attributes
>> Data is processed and feature engineered
>> Categorical features are encoded using One-Hot Encoding
>> The trained ML model predicts:
>>>  BOT or HUMAN
>> Probability scores
>> A rule-based system performs Threat Analysis

📁 project-folder
│── app.py / file.py
│── rfmodel.pkl
│── ohe.pkl
│── requirements.txt

Features Used
    HTTP Method
    API Endpoint
    Status Code
    Response Size
    Session Duration
    Requests per Session
    Time Between Requests
    Failed Requests
    URL Length
    Query Parameters Count
    Payload Size
    Distinct Endpoints Accessed
    Login Attempts
    Request Pattern Entropy

Output
🟢 HUMAN TRAFFIC → Safe
⚠️ BOT DETECTED → Suspicious
🚨 Critical Bot Activity → Block immediately

Includes:

Prediction label
Confidence score
Threat level
Recommended action
