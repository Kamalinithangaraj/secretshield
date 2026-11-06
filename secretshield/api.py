"""Minimal API shell. Repository scanning routes will be added with GitHub OAuth.

Intentionally no arbitrary filesystem-path endpoint: exposing one would let a
remote caller ask the server to read files outside an authorized repository.
"""
from fastapi import FastAPI

app = FastAPI(title="SecretShield API", version="0.2.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "SecretShield", "version": "0.2.0"}
