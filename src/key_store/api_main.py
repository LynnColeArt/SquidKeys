from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("KEY_STORE_API_HOST", "127.0.0.1")
    port = int(os.getenv("KEY_STORE_API_PORT", "8080"))
    uvicorn.run("key_store.api:create_app", factory=True, host=host, port=port)


if __name__ == "__main__":
    main()
