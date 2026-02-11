# Quantum Analyzer

Analizador de seguridad cuántica para TLS/SSL.

## 🚀 **Instalación Rápida**

```bash
# 1. Clonar repositorio
git clone https://github.com/heanczko311299/quantum-analyzer.git
cd quantum-analyzer

# 2. Instalar dependencias (usa pipx internamente)
./quantum.py install

# 3. ¡Listo! Ya puedes usar el analizador
```

### 📝 **Notas importantes:**
- **No uses `pip install -r requirements.txt`** directamente
- El comando `./quantum.py install` maneja la instalación automáticamente
- Si usas `pipx`, asegúrate de tenerlo instalado: `brew install pipx` (macOS) o ver [pipx.pypa.io](https://pipx.pypa.io)

## 🖥️ **Uso**

```bash
# Mostrar ayuda
./quantum.py
./quantum.py help

# Instalar dependencias (si no lo has hecho)
./quantum.py install

# Escanear un dominio específico
./quantum.py run google.com

# Modo interactivo (te pedirá un dominio)
./quantum.py run
```

## ✨ **Características**

✅ Detección de algoritmos PQC (Kyber, Dilithium, Falcon, SPHINCS+)

✅ Análisis de superficie de ataque cuántico   
 
✅ Evaluación de riesgo Store-Now-Decrypt-Later 

✅ Reportes en JSON y Markdown  

✅ Interfaz CLI profesional  

✅ Resultados detallados con visualización en consola  

## 📁 **Estructura del Proyecto**

```
quantum.py              # Punto de entrada principal
requirements.txt        # Dependencias (no instalar directamente)

core/                   # Funcionalidades base
├── __init__.py
├── banner.py           # Banners de la aplicación
└── utils.py            # Utilidades compartidas

modules/                # Lógica de negocio modular
├── __init__.py
├── cli.py              # Argumentos CLI
├── scanner.py          # Orquestador principal
├── parser.py           # Parseo cryptolyze
├── analyzer.py         # Análisis PQC
├── visualizer.py       # Visualización consola
└── reporter.py         # JSON/Markdown reports

results/                # Resultados de escaneos
```

## 📊 **Ejemplo de Salida**

```text
[INFO] Escaneando: google.com
[SUCCESS] Reporte guardado: results/quantum/pqc_tls_google.com.json

 ▸ Motivos:
   • No se detectó KEM PQC...
   • TLS 1.3 soportado: sí

 ▸ Veredicto: NOT QUANTUM-SAFE
 ▸ PQC readiness: [██████████░░░░░░] 45%
```

## ❓ **Solución de Problemas**

### ❌ Error al ejecutar `./quantum.py install`
Asegúrate de que:
- Tienes Python 3.8 o superior instalado
- `pipx` está disponible en tu sistema
- Tienes permisos de ejecución: `chmod +x quantum.py`

### 🔧 Permisos denegados
```bash
chmod +x quantum.py
```

### 📦 Dependencias faltantes
Si `./quantum.py install` falla, intenta:
```bash
# Instalar pipx si no lo tienes
python -m pip install --user pipx
python -m pipx ensurepath

# Luego intenta de nuevo
./quantum.py install
```

## 📊 **Criterios de Evaluación PQC**

✅ El analizador evalúa los siguientes criterios para calcular el porcentaje de preparación cuántica:

✅ Criterio	Peso	Descripción	Verificación
TLS 1.3+	20%	Soporte para TLS 1.3 o superior	cryptolyze --tls-versions

✅ PQC KEM detectado	30%	Presencia de KEM poscuánticos (Kyber, SIKE, etc.)	Análisis de suites criptográficas

✅ PQC Firma detectada	25%	Firmas poscuánticas (Dilithium, Falcon, SPHINCS+)	Análisis de certificados y firmas

✅ Forward Secrecy	15%	Perfect Forward Secrecy habilitado	Ephemeral key exchange

✅ SNI habilitado	10%	Server Name Indication soportado	Extensiones TLS

✅ HSTS configurado	+5%	HTTP Strict Transport Security	Header HTTP adicional


### **Fórmula de cálculo**
```text

PQC readiness = Σ(peso × cumplimiento)
```

Donde cada criterio aporta su peso si se cumple, 0 si no.

Ejemplo con google.com:

    ✅ TLS 1.3: 20%

    ❌ PQC KEM: 0%

    ❌ PQC Firma: 0%

    ✅ Forward Secrecy: 15%

    ✅ SNI: 10%

    ✅ HSTS: +5%

    Total: 50%

### **Visualización en consola**
```text

PQC readiness: [██████████░░░░░░] 50%

```

## 🤝 **Contribuir**

1. Haz fork del repositorio
2. Crea una rama: `git checkout -b mi-feature`
3. Realiza tus cambios
4. Haz commit: `git commit -m 'Añadir feature'`
5. Haz push: `git push origin mi-feature`
6. Abre un Pull Request

## 📄 **Licencia**

MIT License - ver [LICENSE](LICENSE) para más detalles.
