from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
from urllib.parse import urlparse
import re

app = Flask(__name__)
CORS(app)

model = joblib.load('models/random_forest_model.pkl')
feature_list = joblib.load('models/selected_features.pkl')

def extract_features_from_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.netloc

    def count_char(char, text):
        return text.count(char)

    def is_ip(domain):
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))

    features = {
        'qty_slash_url': count_char('/', url),
        'length_url': len(url),
        'domain_length': len(hostname),
        'qty_hyphen_url': count_char('-', url),
        'qty_dot_url': count_char('.', url),
        'qty_mx_servers': 0,
        'qty_nameservers': 0,
        'qty_redirects': 0,
        'domain_spf': 0,
        'tls_ssl_certificate': 0,
        'qty_and_url': count_char('&', url),
        'qty_at_url': count_char('@', url),
        'url_shortened': int(any(x in url for x in ['bit.ly', 'tinyurl.com', 'goo.gl'])),
        'qty_percent_url': count_char('%', url),
        'email_in_url': int(bool(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}", url))),
        'domain_in_ip': int(is_ip(hostname)),
        'qty_questionmark_url': count_char('?', url),
        'qty_exclamation_url': count_char('!', url),
        'url_google_index': 0,
        'domain_google_index': 0
    }

    return [features.get(f, 0) for f in feature_list]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        features = extract_features_from_url(url)
        prediction = model.predict([features])[0]
        result = "SAFE" if prediction == 0 else "PHISHING"
        return jsonify({'prediction': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
