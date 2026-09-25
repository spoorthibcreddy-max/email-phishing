import joblib

# Load the trained model
model = joblib.load("models/phishing_model.pkl")


def detect_email(email):
    prediction = model.predict([email])[0]
    
    if prediction == "phishing":
        return "PHISHING EMAIL"
    else:
        return "SAFE EMAIL"


print("====================================")
print(" AI PHISHING EMAIL DETECTION SYSTEM")
print("====================================")

while True:
    email = input("\nEnter an email message: ")

    if email.lower() == "exit":
        print("System closed.")
        break

    result = detect_email(email)

    print("\nResult:", result)