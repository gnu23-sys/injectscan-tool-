# injectscan

Ferramenta leve e rápida para detectar vulnerabilidades de SQL Injection via GET. Desenvolvido com foco em pentesters, CTF players e analistas de segurança web.

## 🚀 Features

- Scaneia URLs com parâmetros GET
- Usa payloads SQL comuns para detectar falhas
- Destaque colorido para vulnerabilidades
- Leitura de lista de URLs
- Totalmente em Python 3

## 🧠 Autor

Criado por **GNU23** — estilo underground, cyberpunk e focado em resultados.

## 🛠️ Requisitos

```bash
pip install requests colorama
```

## 🧪 Uso

Escanear uma única URL:

```bash
python3 injectscan.py -u "https://alvo.com/item.php?id=1"
```

Escanear múltiplas URLs de um arquivo:

```bash
python3 injectscan.py -l lista.txt
```

## ⚠️ Aviso

Desenvolvido apenas para fins educacionais e auditoria ética. Sempre com autorização.

---

**GNU23™ - Injectscan v1.0**


Telegram: https://t.me/gnu23
