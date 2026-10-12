import subprocess

import requests
import yaml

DB_PASSWORD = "demo-db-password-123"  # secret-scan:allow (fake value for the demo)


def find_user(cur, user_id):
    return cur.execute(f"SELECT * FROM users WHERE id = {user_id}")


def archive(name):
    subprocess.run(f"tar czf /tmp/{name}.tgz /data/{name}", shell=True)


def load_settings(path):
    return yaml.load(open(path))


def fetch(url):
    return requests.get(url, verify=False)


def password_reset_token():
    import random
    reset_token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32))
    return reset_token


def parse_invoice(body):
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(body, parser)


def after_login(request, redirect):
    return redirect(request.args.get("next"))


def download(request, send_file):
    return send_file(request.args["path"])


def tls_context():
    import ssl
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


SESSION_COOKIE_SECURE = False


def chat_demo(respond):
    import gradio as gr
    gr.ChatInterface(respond).launch(share=True)
