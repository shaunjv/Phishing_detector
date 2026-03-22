# 🛡️ AI Phishing URL Detector

A machine learning web app that detects whether a URL is **phishing or legitimate** in real time.

## 🚀 Live Demo
https://phishing-detector-btms.onrender.com

## 🧠 How It Works
1. User enters a URL
2. App extracts 87 features from the URL and webpage
3. Random Forest model predicts phishing or legitimate
4. Result is displayed instantly

## 📊 Model Performance
- Algorithm: Random Forest Classifier
- Accuracy: 96.8%
- Dataset: 11,430 URLs (balanced — 50% phishing, 50% legitimate)

## 🛠️ Tech Stack
| Purpose | Tool |
|---|---|
| ML Model | Scikit-learn (Random Forest) |
| Web Framework | Flask |
| Data Processing | Pandas, NumPy |
| Page Scraping | BeautifulSoup, Requests |
| Domain Info | Python-whois, DNSPython |

## ⚙️ Run Locally

**1. Clone the repository**
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

**2. Install dependencies**
pip install -r requirements.txt

**3. Train the model**

Download the dataset from Kaggle: "Web Page Phishing Detection Dataset"
Place dataset_phishing.csv in the project folder, then:
python model.py

**4. Run the app**
python app.py

**5. Open in browser**
http://127.0.0.1:5000

## 📁 Project Structure
```
phishing-detector/
    ├── app.py              # Flask web app
    ├── model.py            # Model training script
    ├── model.pkl           # Trained model
    ├── requirements.txt    # Dependencies
    └── templates/
            └── index.html  # Frontend
```

## 👤 Author
Shaun John Victor — (https://github.com/shaunjv)
