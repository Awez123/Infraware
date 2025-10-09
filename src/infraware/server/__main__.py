#!/usr/bin/env python3
"""
InfraWare Web Server Entry Point
"""

if __name__ == "__main__":
    import uvicorn
    from .main import app
    
    print("🚀 Starting InfraWare Web Server...")
    print("📊 Dashboard will be available at http://127.0.0.1:8001")
    
    uvicorn.run(
        app, 
        host="127.0.0.1", 
        port=8001,
        reload=True
    )