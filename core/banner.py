# core/banner.py
from colorama import Fore, Style

BANNER_ASCII = f"""{Fore.RED}         
 ██████  ██    ██  █████  ███    ██ ████████ ██    ██ ███    ███ 
██    ██ ██    ██ ██   ██ ████   ██    ██    ██    ██ ████  ████ 
██    ██ ██    ██ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██ 
██ ▄▄ ██ ██    ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██ 
 ██████   ██████  ██   ██ ██   ████    ██     ██████  ██      ██ 
    ▀▀                                                           
{Style.RESET_ALL}

░█░█░█▀▀░█▀█░█▀█░█▀▀░▀▀█░█░█░█▀█
░█▀█░█▀▀░█▀█░█░█░█░░░▄▀░░█▀▄░█░█
░▀░▀░▀▀▀░▀░▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀

 Quantum-safe TLS Analyzer v1.0 | CLI Edition
"""

def banner(ascii_art=BANNER_ASCII):
    """Muestra el banner principal."""
    return ascii_art
