import requests

try:
    # Test DLP
    res = requests.post("http://localhost:5000/api/pa10/length-extension", json={"message": "data=100", "suffix": "&admin=1", "hash_type": "DLP"})
    data = res.json()
    print("DLP success:", data["naive"]["success"], data["hmac"]["success"])

    # Test SHA256
    res = requests.post("http://localhost:5000/api/pa10/length-extension", json={"message": "data=100", "suffix": "&admin=1", "hash_type": "SHA256"})
    data = res.json()
    print("SHA256 success:", data["naive"]["success"], data["hmac"]["success"])
except Exception as e:
    print("API Error:", e)
