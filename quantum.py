#!/usr/bin/env python3
# quantum.py — Quantum-safe TLS Analyzer (MAIN CLI)
# -*- coding: utf-8 -*-
"""
CLI principal - Sin menú interactivo.
Uso:
  quantum.py                    # Muestra ayuda
  quantum.py help              # Muestra ayuda
  quantum.py install           # Instala dependencias
  quantum.py run [dominio]     # Escanea dominio
"""

import sys
from colorama import init
from core.banner import banner
from modules.cli import handle_cli_args

def main():
    """Punto de entrada principal."""
    init(autoreset=True)
    
    # Manejar argumentos CLI
    exit_code = handle_cli_args()
    sys.exit(exit_code if isinstance(exit_code, int) else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupción por usuario. Saliendo.")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Error crítico: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)