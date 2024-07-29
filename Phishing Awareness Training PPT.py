Creating a phishing awareness code involves providing employees or users with practical guidance on recognizing, avoiding, and reporting phishing attempts. 
Below is a sample code that can be adapted for use in various organizations:

---------

Phishing Awareness Code of Conduct

Objective:
To safeguard our organization from phishing attacks by ensuring all employees are aware of potential threats and know how to respond appropriately.

Scope:
This code applies to all employees, contractors, and third-party service providers who have access to the organization's information systems.

1. Recognizing Phishing Attempts

- Suspicious Emails:
  - Sender: Verify the sender's email address. Be cautious of emails from unfamiliar or unexpected sources.
  - Subject Line: Be wary of urgent or alarming subject lines that pressure you to act quickly.
  - Content: Look for grammatical errors, spelling mistakes, or inconsistent formatting.
  - Attachments and Links: Be cautious with unsolicited attachments and links. Hover over links to verify their destination.

- Suspicious Websites:
  - URL: Check the URL for accuracy. Look for misspellings or unusual domain names.
  - Security Indicators: Ensure the website uses HTTPS and has a valid security certificate.
  - Content: Look for signs of a legitimate website, such as professional design, contact information, and proper functionality.

2. Avoiding Phishing Traps

- Do Not Share Sensitive Information: Never provide personal, financial, or login information in response to an unsolicited email or pop-up.
- Verify Requests: If you receive a request for sensitive information, verify its legitimacy by contacting the sender through a known, trusted method.
- Avoid Clicking Links: Do not click on links in unsolicited emails or messages. Instead, type the URL directly into your browser or use a bookmark.

3. Reporting Phishing Attempts

- Immediate Reporting: Report any suspected phishing attempts to the IT department immediately.
- Forward Suspicious Emails: Forward suspicious emails to phishing@yourorganization.com for investigation.
- Incident Documentation: Document the details of the phishing attempt, including the sender's information, email content, and any actions taken.

4. Training and Education

- Regular Training: Participate in mandatory phishing awareness training sessions.
- Stay Informed: Keep up-to-date with the latest phishing tactics and organizational policies through regular communications from the IT department.
- Share Knowledge: Educate your colleagues on how to recognize and avoid phishing attempts.

5. Enforcement and Compliance

- Policy Adherence: All employees must adhere to this Phishing Awareness Code of Conduct.
- Non-Compliance: Failure to comply with this code may result in disciplinary action, up to and including termination of employment.
- Continuous Improvement: The organization will regularly review and update this code to address emerging threats and ensure best practices.

--------------

Remember: Phishing attacks can compromise our organization’s security and your personal information. Stay vigilant, be cautious, and report any suspicious activity.

Creating a code to detect phishing attacks typically involves analyzing URLs, email content, and metadata to identify suspicious patterns. 
Here’s an example in Python that utilizes some common techniques to detect phishing URLs using machine learning and heuristic methods. 
This script uses a pre-trained model for URL classification and checks for common phishing characteristics.

First, make sure you have the necessary libraries installed:
pip install scikit-learn pandas numpy

script that uses a simple logistic regression model to classify URLs as phishing or not:
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
import re
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Sample phishing dataset (you can replace this with a real dataset)
data = {
    'url': [
        'http://example.com/login', 'http://phishingsite.com/bank-login',
        'https://secure.example.com', 'http://malicioussite.com/account-update',
        'https://trusted.com/home', 'http://fraudsite.com/payments'
    ],
    'label': [0, 1, 0, 1, 0, 1] # 0: not phishing, 1: phishing
}

df = pd.DataFrame(data)

# Feature extraction using TF-IDF
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['url'])
y = df['label']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train a logistic regression model
model = LogisticRegression()
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
print(f'Accuracy: {accuracy_score(y_test, y_pred)}')

# Function to detect phishing URLs
def detect_phishing(url):
    features = vectorizer.transform([url])
    prediction = model.predict(features)
    return 'Phishing' if prediction == 1 else 'Not phishing'

# Test the function
test_urls = [
    'http://legitwebsite.com', 'http://phishingsite.com/verify-account',
    'https://securelegit.com', 'http://malicioussite.com/update-info'
]

for url in test_urls:
    result = detect_phishing(url)
    print(f'URL: {url} - {result}')

--------------------------------------------------------------------------------------------------------------------------------------------------------------------
Explanation:
Dataset Preparation: The sample dataset includes a few URLs marked as phishing or not. Replace this with a larger, real dataset for better performance.
Feature Extraction: We use the TF-IDF vectorizer to convert URLs into numerical features.
Model Training: We train a logistic regression model using the extracted features.
Detection Function: The detect_phishing function takes a URL as input, transforms it using the vectorizer, and predicts if it's phishing using the trained model.
This script is a basic example and can be expanded and improved. For real-world applications, consider the following:

Using more advanced models: Such as Random Forests, SVMs, or deep learning models.
Adding more features: Such as WHOIS data, URL length, presence of special characters, and more.
Regular updates: Continuously update the dataset and retrain the model to keep up with new phishing 
