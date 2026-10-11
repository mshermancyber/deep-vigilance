# tp-ssti.py: SSTI via render_template_string with user input
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # VULNERABLE: user input in template string
    return render_template_string('<h1>Hello {{ ' + name + ' }}!</h1>')
