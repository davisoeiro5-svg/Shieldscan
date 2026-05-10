from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import re

app = Flask(__name__)
CORS(app)  # Permite o frontend se comunicar com o backend

# ─── Definição dos headers analisados ───────────────────────────────────────

HEADERS_INFO = {
    "content-security-policy": {
        "label": "Content-Security-Policy",
        "desc": "Controla quais recursos o navegador pode carregar. Protege contra XSS.",
        "tip": "Adicione: Content-Security-Policy: default-src 'self'",
        "weight": 3
    },
    "strict-transport-security": {
        "label": "Strict-Transport-Security",
        "desc": "Força o uso de HTTPS, impedindo ataques de downgrade para HTTP.",
        "tip": "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "weight": 2
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "desc": "Impede que o site seja carregado em iframes. Protege contra Clickjacking.",
        "tip": "Adicione: X-Frame-Options: DENY ou SAMEORIGIN",
        "weight": 2
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "desc": "Impede MIME sniffing, evitando execução de arquivos maliciosos.",
        "tip": "Adicione: X-Content-Type-Options: nosniff",
        "weight": 1
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "desc": "Controla quais informações de URL são enviadas a sites externos.",
        "tip": "Adicione: Referrer-Policy: strict-origin-when-cross-origin",
        "weight": 1
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "desc": "Controla acesso a câmera, microfone e geolocalização.",
        "tip": "Adicione: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "weight": 1
    }
}

# ─── Funções auxiliares ──────────────────────────────────────────────────────

def normalizar_url(url: str) -> str:
    """Garante que a URL tenha um esquema válido."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def calcular_score(resultados: dict) -> str:
    """Calcula nota de A a D baseado nos headers presentes."""
    total = 0
    maximo = 0
    for key, r in resultados.items():
        peso = HEADERS_INFO[key]["weight"]
        maximo += peso
        if r["status"] == "pass":
            total += peso

    percentual = (total / maximo) * 100 if maximo > 0 else 0

    if percentual >= 85:
        return "A"
    elif percentual >= 65:
        return "B"
    elif percentual >= 40:
        return "C"
    else:
        return "D"


def analisar_headers(headers_recebidos: dict) -> dict:
    """Compara os headers recebidos com os esperados."""
    # Normaliza as chaves para minúsculo
    headers_lower = {k.lower(): v for k, v in headers_recebidos.items()}

    resultados = {}

    for key, info in HEADERS_INFO.items():
        if key in headers_lower:
            resultados[key] = {
                "status": "pass",
                "value": headers_lower[key],
                "label": info["label"],
                "desc": info["desc"],
                "tip": info["tip"]
            }
        else:
            resultados[key] = {
                "status": "fail",
                "value": None,
                "label": info["label"],
                "desc": info["desc"],
                "tip": info["tip"]
            }

    return resultados


# ─── Rotas ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"status": "ShieldScan API online 🛡️"})


@app.route("/scan", methods=["POST"])
def scan():
    dados = request.get_json()

    if not dados or "url" not in dados:
        return jsonify({"erro": "Nenhuma URL enviada."}), 400

    url = normalizar_url(dados["url"])

    # Valida formato básico da URL
    if not re.match(r"https?://[^\s/$.?#].[^\s]*", url):
        return jsonify({"erro": "URL inválida."}), 400

    try:
        resposta = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "ShieldScan/1.0 Security Analyzer"
            }
        )

        dominio = resposta.url.split("/")[2]
        resultados = analisar_headers(dict(resposta.headers))
        score = calcular_score(resultados)

        return jsonify({
            "url": dominio,
            "url_final": resposta.url,
            "status_code": resposta.status_code,
            "score": score,
            "resultados": resultados
        })

    except requests.exceptions.SSLError:
        return jsonify({"erro": "Erro de SSL. O site pode ter certificado inválido."}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"erro": "Não foi possível conectar ao site. Verifique a URL."}), 400
    except requests.exceptions.Timeout:
        return jsonify({"erro": "O site demorou demais para responder (timeout)."}), 408
    except Exception as e:
        return jsonify({"erro": f"Erro inesperado: {str(e)}"}), 500


# ─── Iniciar servidor ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🛡️  ShieldScan API rodando em http://localhost:5000")
    import os
port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
