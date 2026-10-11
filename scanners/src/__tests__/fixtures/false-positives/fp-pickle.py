# fp-pickle.py: yaml.safe_load (not yaml.load) — SAFE
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/config', methods=['POST'])
def load_config():
    data = request.get_data()
    # SAFE: yaml.safe_load prevents arbitrary code execution
    config = yaml.safe_load(data)
    return str(config)
