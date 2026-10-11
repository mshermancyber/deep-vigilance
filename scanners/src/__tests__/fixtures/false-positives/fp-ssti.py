# fp-ssti.py: Jinja2 render_template (auto-escaped) — SAFE
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # SAFE: render_template uses auto-escaping, template is a separate file
    return render_template('hello.html', name=name)
