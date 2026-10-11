# tp-pickle.py: Unsafe pickle.load with user data
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_data()
    # VULNERABLE: unpickling untrusted data
    obj = pickle.loads(data)
    return str(obj)
