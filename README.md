🤖 API Bot Detection using Machine Learning

This project detects automated bots hitting your APIs in real-time using Machine Learning. The API predicts whether a request is from a bot or a human based on request patterns and metadata. The project is deployed using FastAPI and can be run locally or using Docker.

📌 Problem Statement

APIs are often targeted by bots that generate spam, overload servers, or attempt brute-force attacks. This project aims to identify bot traffic automatically to improve security and server efficiency.

🚀 Project Workflow

Data Collection – API logs and request data

Data Cleaning & Preprocessing

Feature Engineering – Create numerical & categorical features

Model Building – Supervised ML classifier

Model Evaluation – Accuracy, precision, recall, F1-score

API Deployment – FastAPI with Uvicorn / Docker

🛠️ Technologies Used

Python 3.9

FastAPI

Uvicorn

Scikit-learn

Pandas & NumPy

Joblib

Docker

⚙️ How to Run the Project (Windows - Command Prompt)

1️⃣ Open Command Prompt Press: Win + R → type cmd → Enter

2️⃣ Navigate to Project Folder cd C:\Users\RAVI\Desktop\API-Bot-Detection

3️⃣ Install Required Libraries pip install -r requirements.txt

4️⃣ Run FastAPI Application uvicorn main:app --host 0.0.0.0 --port 8000

5️⃣ Open in Browser http://localhost:8000/docs You will see the Swagger UI to test the API endpoints.

🐳 Docker Deployment

1️⃣ Build Docker image: docker build -t bot-detection-api .

2️⃣ Run Docker container: docker run -p 8000:8000 bot-detection-api

The API is now accessible at: http://localhost:8000/docs

3️⃣ Stop container (if needed): docker ps # list running containers docker stop <container_id>

4️⃣ Remove container (optional cleanup): docker rm <container_id>

🌐 Input Features

http_method – HTTP method (GET, POST, etc.)

endpoint – API endpoint

status_code – Response code

response_size – Size of response in bytes

session_duration – Duration of session

requests_per_session – Total requests in session

time_between_requests – Average time between requests

failed_requests – Number of failed requests

url_length – Length of URL

query_param_count – Number of query parameters

payload_size – Request payload size

distinct_endpoints_accessed – Number of endpoints accessed

login_attempts – Number of login attempts

request_pattern_entropy – Entropy of request pattern

📈 Model Performance

(Replace with your metrics)

F1-score: 0.89

Algorithm Used: Supervised classifier (RandomForest)

🎯 Key Features of the App

✅ Real-time bot detection

✅ Simple API interface using FastAPI

✅ Can be deployed locally or in Docker

✅ Returns bot or human prediction

🔮 Future Improvements

Deploy on cloud ( Docker / Streamlit)

Add Network features IP Address 

Integrate with API Gateway for automated blocking

Add dashboard to visualize bot activity

Improve model with deep learning or real-time streaming data
