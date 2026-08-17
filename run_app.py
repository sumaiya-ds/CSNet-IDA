"""
CSNet-IDA Prototype Web Application Launcher.
"""

import sys
import uvicorn

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8000
    print("=" * 70)
    print("  CSNet-IDA: Two-Stage Machine Learning Intrusion Detection System")
    print("=" * 70)
    print(f"  Starting web dashboard at: http://{host}:{port}")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 70)

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
