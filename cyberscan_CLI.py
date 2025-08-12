#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERSCAN PRO+ - Scanner de sécurité réseau local
Projet final de cybersécurité
"""

import socket
import subprocess
import datetime
import time
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

class CyberScanPro:
    def __init__(self):
        self.invalid_domains_count = 0
        self.max_invalid_domains = 3
        self.timeout = 5
        self.common_subdomains = ['www', 'mail', 'admin', 'ftp', 'ssh', 'dev', 'test', 'blog', 'shop', 'api']
        self.ports_to_scan = [22, 80, 443, 3306]
        
        # Couleurs pour l'affichage
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m',
            'bold': '\033[1m'
        }

    def print_banner(self):
        """Affiche la bannière du programme"""
        banner = f"""
{self.colors['cyan']}{self.colors['bold']}
╔══════════════════════════════════════════════════════════════╗
║                    CYBERSCAN PRO+                            ║
║              Scanner de sécurité réseau                      ║
║                      Version 1.0                             ║
╚══════════════════════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(banner)

    def colorize(self, text, color):
        """Colore le texte"""
        return f"{self.colors.get(color, '')}{text}{self.colors['reset']}"

    def resolve_domain(self, domain):
        """Résout l'adresse IP d'un domaine"""
        try:
            ip = socket.gethostbyname(domain)
            print(f"[+] Résolution DNS: {self.colorize(domain, 'green')} -> {self.colorize(ip, 'yellow')}")
            return ip
        except socket.gaierror:
            print(f"[-] Erreur: Impossible de résoudre {self.colorize(domain, 'red')}")
            return None

    def ping_domain(self, domain):
        """Ping le domaine 3 fois et calcule le taux de réussite"""
        print(f"\n[*] Ping de {self.colorize(domain, 'blue')}...")
        success_count = 0
        ping_times = []
        
        for i in range(3):
            try:
                # Utilise ping système
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['ping', '-n', '1', '-w', '3000', domain], 
                                          capture_output=True, text=True, timeout=5)
                else:  # Unix/Linux/Mac
                    result = subprocess.run(['ping', '-c', '1', '-W', '3', domain], 
                                          capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    success_count += 1
                    # Extrait le temps de ping
                    if os.name == 'nt':
                        match = re.search(r'temps[<=](\d+)ms', result.stdout)
                    else:
                        match = re.search(r'time=(\d+\.?\d*)', result.stdout)
                    
                    if match:
                        ping_times.append(float(match.group(1)))
                    
                    print(f"  Ping {i+1}: {self.colorize('SUCCESS', 'green')}")
                else:
                    print(f"  Ping {i+1}: {self.colorize('FAILED', 'red')}")
                    
            except subprocess.TimeoutExpired:
                print(f"  Ping {i+1}: {self.colorize('TIMEOUT', 'red')}")
            except Exception as e:
                print(f"  Ping {i+1}: {self.colorize('ERROR', 'red')}")
        
        success_rate = (success_count / 3) * 100
        avg_time = sum(ping_times) / len(ping_times) if ping_times else 0
        
        print(f"[+] Taux de réussite: {self.colorize(f'{success_rate:.1f}%', 'green')}")
        if avg_time > 0:
            print(f"[+] Temps moyen: {self.colorize(f'{avg_time:.1f}ms', 'yellow')}")
        
        return success_rate, avg_time

    def analyze_ttl(self, domain):
        """Analyse le TTL pour deviner le système d'exploitation"""
        print(f"\n[*] Analyse TTL pour {self.colorize(domain, 'blue')}...")
        
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', domain], 
                                      capture_output=True, text=True, timeout=5)
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:  # Unix/Linux/Mac
                result = subprocess.run(['ping', '-c', '1', domain], 
                                      capture_output=True, text=True, timeout=5)
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                print(f"[+] TTL détecté: {self.colorize(str(ttl), 'yellow')}")
                
                # Analyse du système d'exploitation basée sur TTL
                if ttl <= 64:
                    if ttl > 32:
                        os_guess = "Linux/Unix"
                    else:
                        os_guess = "Ancien système Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl <= 255:
                    os_guess = "Cisco/Routeur"
                else:
                    os_guess = "Système inconnu"
                
                print(f"[+] Système probable: {self.colorize(os_guess, 'green')}")
                return ttl, os_guess
            else:
                print(f"[-] TTL non détecté")
                return None, "Inconnu"
                
        except Exception as e:
            print(f"[-] Erreur lors de l'analyse TTL: {str(e)}")
            return None, "Erreur"

    def reverse_dns(self, ip):
        """Effectue une résolution DNS inverse"""
        print(f"\n[*] Résolution DNS inverse pour {self.colorize(ip, 'blue')}...")
        
        try:
            hostname = socket.gethostbyaddr(ip)
            print(f"[+] Nom de machine: {self.colorize(hostname[0], 'green')}")
            return hostname[0]
        except socket.herror:
            print(f"[-] Aucun nom de machine trouvé pour {ip}")
            return None

    def scan_port(self, ip, port):
        """Scanne un port spécifique"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_banner(self, ip, port):
        """Tente de récupérer la bannière d'un service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Envoie des données selon le port
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH envoie sa bannière automatiquement
            elif port == 443:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200] if banner else None
        except:
            return None

    def scan_ports(self, ip):
        """Scanne les ports spécifiés"""
        print(f"\n[*] Scan des ports sur {self.colorize(ip, 'blue')}...")
        
        open_ports = []
        port_info = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in self.ports_to_scan}
            
            for future in future_to_port:
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        print(f"  Port {port}: {self.colorize('OUVERT', 'green')}")
                        
                        # Tente de récupérer la bannière
                        banner = self.get_banner(ip, port)
                        if banner:
                            print(f"    Bannière: {self.colorize(banner[:100] + '...', 'yellow')}")
                            port_info[port] = banner
                        else:
                            port_info[port] = "Pas de bannière"
                    else:
                        print(f"  Port {port}: {self.colorize('FERMÉ', 'red')}")
                except Exception as e:
                    print(f"  Port {port}: {self.colorize('ERREUR', 'red')}")
        
        return open_ports, port_info

    def http_request(self, domain, ip):
        """Effectue une requête HTTP manuelle"""
        print(f"\n[*] Test de connexion HTTP sur {self.colorize(domain, 'blue')}...")
        
        try:
            # Test HTTP (port 80)
            if self.scan_port(ip, 80):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, 80))
                
                request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: CyberScanPro/1.0\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                if response:
                    status_line = response.split('\n')[0]
                    print(f"[+] Réponse HTTP: {self.colorize(status_line.strip(), 'green')}")
                    return True, status_line.strip()
                else:
                    print(f"[-] Aucune réponse HTTP")
                    return False, None
            else:
                print(f"[-] Port 80 fermé")
                return False, None
                
        except Exception as e:
            print(f"[-] Erreur HTTP: {str(e)}")
            return False, None

    def check_https(self, ip):
        """Vérifie si HTTPS est disponible"""
        print(f"\n[*] Vérification HTTPS...")
        
        if self.scan_port(ip, 443):
            print(f"[+] HTTPS: {self.colorize('DISPONIBLE', 'green')} (Port 443 ouvert)")
            return True
        else:
            print(f"[-] HTTPS: {self.colorize('NON DISPONIBLE', 'red')} (Port 443 fermé)")
            return False

    def scan_subdomains(self, domain):
        """Scanne des sous-domaines communs"""
        print(f"\n[*] Scan des sous-domaines de {self.colorize(domain, 'blue')}...")
        
        found_subdomains = []
        
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                print(f"  {full_domain}: {self.colorize('TROUVÉ', 'green')} -> {ip}")
                found_subdomains.append((full_domain, ip))
            except socket.gaierror:
                print(f"  {full_domain}: {self.colorize('NON TROUVÉ', 'red')}")
        
        return found_subdomains

    def generate_ascii_chart(self, open_ports):
        """Génère un graphique ASCII des ports ouverts"""
        print(f"\n[*] Graphique ASCII des ports:")
        
        chart = "\n  Ports: "
        for port in self.ports_to_scan:
            if port in open_ports:
                chart += f"{self.colorize('■', 'green')} {port} "
            else:
                chart += f"{self.colorize('□', 'red')} {port} "
        
        chart += f"\n  Légende: {self.colorize('■', 'green')} = Ouvert, {self.colorize('□', 'red')} = Fermé"
        print(chart)
        
        return chart

    def generate_report(self, domain, scan_results):
        """Génère un rapport de scan"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = f"rapport_{domain.replace('.', '_')}.txt"
        
        print(f"\n[*] Génération du rapport: {self.colorize(filename, 'blue')}")
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write(f"RAPPORT CYBERSCAN PRO+ - {domain.upper()}\n")
            f.write("="*60 + "\n")
            f.write(f"Date du scan: {timestamp}\n")
            f.write(f"Domaine analysé: {domain}\n")
            f.write("-"*60 + "\n\n")
            
            # Résolution DNS
            if scan_results.get('ip'):
                f.write(f"RÉSOLUTION DNS:\n")
                f.write(f"  Adresse IP: {scan_results['ip']}\n")
                if scan_results.get('reverse_dns'):
                    f.write(f"  Nom de machine: {scan_results['reverse_dns']}\n")
                f.write("\n")
            
            # Ping
            if scan_results.get('ping_success_rate') is not None:
                f.write(f"TEST DE CONNECTIVITÉ:\n")
                f.write(f"  Taux de réussite ping: {scan_results['ping_success_rate']:.1f}%\n")
                if scan_results.get('ping_avg_time'):
                    f.write(f"  Temps moyen: {scan_results['ping_avg_time']:.1f}ms\n")
                f.write("\n")
            
            # TTL et OS
            if scan_results.get('ttl'):
                f.write(f"ANALYSE SYSTÈME:\n")
                f.write(f"  TTL: {scan_results['ttl']}\n")
                f.write(f"  Système probable: {scan_results['os_guess']}\n")
                f.write("\n")
            
            # Ports
            if scan_results.get('open_ports'):
                f.write(f"SCAN DES PORTS:\n")
                for port in scan_results['open_ports']:
                    f.write(f"  Port {port}: OUVERT\n")
                    if scan_results.get('port_info', {}).get(port):
                        f.write(f"    Bannière: {scan_results['port_info'][port][:100]}...\n")
                f.write("\n")
            
            # Services web
            if scan_results.get('http_status'):
                f.write(f"SERVICES WEB:\n")
                f.write(f"  HTTP: {scan_results['http_status']}\n")
                f.write(f"  HTTPS: {'Disponible' if scan_results.get('https_available') else 'Non disponible'}\n")
                f.write("\n")
            
            # Sous-domaines
            if scan_results.get('subdomains'):
                f.write(f"SOUS-DOMAINES TROUVÉS:\n")
                for subdomain, ip in scan_results['subdomains']:
                    f.write(f"  {subdomain} -> {ip}\n")
                f.write("\n")
            
            f.write("="*60 + "\n")
            f.write("Rapport généré par CYBERSCAN PRO+ v1.0\n")
        
        print(f"[+] Rapport sauvegardé: {self.colorize(filename, 'green')}")

    def update_history(self, domain, scan_results):
        """Met à jour l'historique global"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open("historique.txt", "a", encoding='utf-8') as f:
            f.write(f"{timestamp} - Scan de {domain} - IP: {scan_results.get('ip', 'N/A')} - ")
            f.write(f"Ports ouverts: {len(scan_results.get('open_ports', []))}\n")
        
        print(f"[+] Historique mis à jour")

    def is_valid_domain(self, domain):
        """Vérifie si le domaine est valide"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$' 
        )
        return bool(domain_pattern.match(domain)) and len(domain) <= 253

    def scan_domain(self, domain):
        """Effectue un scan complet d'un domaine"""
        print(f"\n{self.colorize('='*60, 'cyan')}")
        print(f"DÉBUT DU SCAN DE {self.colorize(domain.upper(), 'bold')}")
        print(f"{self.colorize('='*60, 'cyan')}")
        
        scan_results = {}
        
        # 1. Résolution DNS
        ip = self.resolve_domain(domain)
        if not ip:
            return None
        scan_results['ip'] = ip
        
        # 2. Ping
        ping_rate, ping_time = self.ping_domain(domain)
        scan_results['ping_success_rate'] = ping_rate
        scan_results['ping_avg_time'] = ping_time
        
        # 3. Analyse TTL
        ttl, os_guess = self.analyze_ttl(domain)
        scan_results['ttl'] = ttl
        scan_results['os_guess'] = os_guess
        
        # 4. Reverse DNS
        reverse_dns = self.reverse_dns(ip)
        scan_results['reverse_dns'] = reverse_dns
        
        # 5. Scan des ports
        open_ports, port_info = self.scan_ports(ip)
        scan_results['open_ports'] = open_ports
        scan_results['port_info'] = port_info
        
        # 6. Test HTTP
        http_success, http_status = self.http_request(domain, ip)
        scan_results['http_status'] = http_status
        
        # 7. Vérification HTTPS
        https_available = self.check_https(ip)
        scan_results['https_available'] = https_available
        
        # 8. Scan sous-domaines
        subdomains = self.scan_subdomains(domain)
        scan_results['subdomains'] = subdomains
        
        # 9. Graphique ASCII
        ascii_chart = self.generate_ascii_chart(open_ports)
        
        # 10. Génération du rapport
        self.generate_report(domain, scan_results)
        
        # 11. Mise à jour de l'historique
        self.update_history(domain, scan_results)
        
        print(f"\n{self.colorize('='*60, 'green')}")
        print(f"SCAN TERMINÉ POUR {self.colorize(domain.upper(), 'bold')}")
        print(f"{self.colorize('='*60, 'green')}")
        
        return scan_results

    def run(self):
        """Fonction principale du programme"""
        self.print_banner()
        
        print(f"{self.colorize('Instructions:', 'yellow')}")
        print("- Entrez un nom de domaine à analyser (ex: google.com)")
        print("- Tapez 'exit' pour quitter le programme")
        print("- Le programme se bloque après 3 domaines invalides consécutifs")
        print("-" * 60)
        
        while True:
            try:
                domain = input(f"\n{self.colorize('Entrez un domaine à scanner:', 'cyan')} ").strip()
                
                if domain.lower() == 'exit':
                    print(f"\n{self.colorize('Au revoir! Merci d\'avoir utilisé CYBERSCAN PRO+', 'green')}")
                    break
                
                if not domain:
                    print(f"{self.colorize('Erreur: Veuillez entrer un domaine valide', 'red')}")
                    continue
                
                # Validation du domaine
                if not self.is_valid_domain(domain):
                    print(f"{self.colorize('Erreur: Format de domaine invalide', 'red')}")
                    self.invalid_domains_count += 1
                    
                    if self.invalid_domains_count >= self.max_invalid_domains:
                        print(f"\n{self.colorize('PROGRAMME BLOQUÉ: Trop de domaines invalides consécutifs', 'red')}")
                        break
                    
                    print(f"{self.colorize(f'Attention: {self.invalid_domains_count}/{self.max_invalid_domains} domaines invalides', 'yellow')}")
                    continue
                
                # Reset du compteur si domaine valide
                self.invalid_domains_count = 0
                
                # Lancement du scan
                start_time = time.time()
                result = self.scan_domain(domain)
                end_time = time.time()
                
                if result:
                    print(f"\n{self.colorize(f'Temps total du scan: {end_time - start_time:.2f} secondes', 'magenta')}")
                else:
                    print(f"{self.colorize('Scan échoué pour ce domaine', 'red')}")
                    self.invalid_domains_count += 1
                    
                    if self.invalid_domains_count >= self.max_invalid_domains:
                        print(f"\n{self.colorize('PROGRAMME BLOQUÉ: Trop de domaines invalides consécutifs', 'red')}")
                        break
                
            except KeyboardInterrupt:
                print(f"\n\n{self.colorize('Scan interrompu par l\'utilisateur', 'yellow')}")
                break
            except Exception as e:
                print(f"\n{self.colorize(f'Erreur inattendue: {str(e)}', 'red')}")
                continue

if __name__ == "__main__":
    # Création et lancement du scanner
    scanner = CyberScanPro()
    scanner.run()