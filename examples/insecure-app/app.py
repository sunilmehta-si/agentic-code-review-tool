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
