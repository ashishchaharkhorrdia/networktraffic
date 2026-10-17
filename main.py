#!/usr/bin/env python3
"""CyberNinjas - Centralized Network Traffic & Security Analysis Tool Entrypoint."""

import sys
import argparse
import uvicorn
from app.config import HOST, PORT
from app.collector.bandwidth import BandwidthCollector

def print_banner(host: str, port: int):
    collector = BandwidthCollector()
    default_info = collector.get_default_interface()
    
    cyan = "\033[96m"
    emerald = "\033[92m"
    bold = "\033[1m"
    reset = "\033[0m"

    banner_art = r"""
   ____      _               _   _ _       _           
  / ___|   _| |__   ___ _ __| \ | (_)_ __ (_) __ _ ___ 
 | |  | | | | '_ \ / _ \ '__|  \| | | '_ \| |/ _` / __|
 | |__| |_| | |_) |  __/ |  | |\  | | | | | | (_| \__ \
  \____\__, |_.__/ \___|_|  |_| \_|_|_| |_|/ |\__,_|___/
       |___/                              |__/          
    """
    print(f"{cyan}{bold}{banner_art}{reset}")
    print(f"    {emerald}Network Traffic & Security Analysis Platform{reset}\n")
    print(f"  {bold}Default Interface :{reset} {default_info['interface']}")
    print(f"  {bold}Default Gateway   :{reset} {default_info['gateway']}")
    print(f"  {bold}Dashboard URL     :{reset} {cyan}http://{host if host != '0.0.0.0' else 'localhost'}:{port}{reset}")
    print(f"  {bold}Status            :{reset} {emerald}ONLINE & MONITORING{reset}\n")

def main():
    parser = argparse.ArgumentParser(description="CyberNinjas - Network Traffic & Security Analysis Tool")
    parser.add_argument("--host", default=HOST, help=f"Host to bind (default: {HOST})")
    parser.add_argument("--port", type=int, default=PORT, help=f"Port to bind (default: {PORT})")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    print_banner(args.host, args.port)
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main()
