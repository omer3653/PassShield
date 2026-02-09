# PassShield 🛡️ | Password Strength & Entropy Analyzer

**PassShield** is a web-based cybersecurity tool designed to help users understand the strength of their passwords. It calculates mathematical entropy and estimates the time required for a brute-force attack in real-time.

## 🚀 Live Demo
Check out the live application here: 
](https://passshield.onrender.com/)
## ✨ Key Features
* **Real-Time Analysis:** Instant feedback on password strength as you type.
* **Entropy Calculation:** Uses information theory to determine the complexity of the input.
* **Crack Time Estimation:** Predicts how long a standard brute-force attack would take to succeed.
* **Visual Indicators:** Dynamic UI changes (color and bars) based on security tiers (Weak, Medium, Strong).
* **Social Engineering Detection (New!):** Identifies if the password contains sensitive personal patterns like Israeli phone numbers or ID numbers.

## 🛡️ Security Logic & Pattern Recognition
The tool doesn't just check for length; it looks for vulnerable patterns:
* **PII Detection:** Automatically flags potential Phone Numbers (`05X-XXXXXXX`) and ID numbers (9 digits).
* **Repetition Analysis:** Warns against using long sequences of the same character (e.g., `aaaaa`).
* **Entropy Pool:** Calculates complexity based on 4 character sets: Lowercase, Uppercase, Numbers, and Special characters.

## 🛠️ Tech Stack
* **Backend:** Python (Flask Framework)
* **Frontend:** HTML5, CSS3, JavaScript
* **Server/WSGI:** Gunicorn
* **Deployment:** Render
* **Version Control:** Git & GitHub

## 📝 How to Run Locally
1. Clone the repository:
   ```bash
   git clone [https://github.com/omer3653/PassShield.git](https://github.com/omer3653/PassShield.git)
