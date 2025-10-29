#!/usr/bin/env python3
"""
WebSecScanner - Application Launcher
Quick start script for running the web application
"""
import os
import sys
import uvicorn

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("  🔒 WebSecScanner - Web Application Security Scanner")
    print("="*70)
    print("\n🚀 Iniciando servidor...\n")
    
    # Determine host based on OS
    default_host = "127.0.0.1" if os.name == "nt" else "0.0.0.0"
    host = os.getenv("HOST", default_host)
    port = int(os.getenv("PORT", 8000))
    
    print(f"📡 Servidor: http://{host}:{port}")
    print(f"📚 API Docs: http://127.0.0.1:{port}/docs")
    print(f"👤 Login: admin@websecscanner.com / admin123")
    print("\n" + "="*70 + "\n")
    
    # Run uvicorn
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=os.getenv("DEBUG", "False").lower() == "true",
        app_dir="src"
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Servidor encerrado pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erro ao iniciar servidor: {e}")
        sys.exit(1)
