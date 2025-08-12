#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERSCAN PRO+ GUI - Interface graphique pour scanner de sécurité réseau
Version GUI avec tkinter
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import subprocess
import datetime
import time
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import ipaddress
import csv
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests

class CyberScanProGUI:
    def __init__(self):
        # Variables de configuration
        self.invalid_domains_count = 0
        self.max_invalid_domains = 3
        self.timeout = 5
        self.common_subdomains = ['www', 'mail', 'admin', 'ftp', 'ssh', 'dev', 'test', 'blog', 'shop', 'api']
        self.ports_to_scan = [22, 80, 443, 3306, 21, 25, 53, 110, 993, 995]
        self.vulndb_api_key = ""
        
        # Variables d'état
        self.scanning = False
        self.current_scan_results = {}
        self.scan_history = []

        # Charger la configuration
        self.load_config()
        
        # Configuration de l'interface
        self.setup_gui()
        
    def setup_gui(self):
        """Configure l'interface graphique principale"""
        self.root = tk.Tk()
        self.root.title("CyberScan Pro+ - Scanner de Sécurité Réseau")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#3498db')
        style.configure('Accent.TButton', font=('Arial', 10, 'bold'))
        
        
        self.create_widgets()
        
    def create_widgets(self):
        """Crée tous les widgets de l'interface"""
        # Titre principal
        title_frame = tk.Frame(self.root, bg='#2c3e50')
        title_frame.pack(fill='x', padx=10, pady=10)
        
        title_label = tk.Label(title_frame, text="🛡️ CYBERSCAN PRO+ 🛡️", 
                              font=('Arial', 20, 'bold'), 
                              fg='#3498db', bg='#2c3e50')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Scanner de Sécurité Réseau - Version GUI", 
                                 font=('Arial', 12), 
                                 fg='#ecf0f1', bg='#2c3e50')
        subtitle_label.pack()
        
        # Frame principal avec onglets
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Onglet Scanner
        self.create_scanner_tab()
        
        # Onglet Résultats
        self.create_results_tab()
        
        # Onglet Historique
        self.create_history_tab()

        # Onglet Réseau
        self.create_network_tab()
        
        # Onglet Configuration
        self.create_config_tab()
        
        # Barre de statut
        self.create_status_bar()
        
    def create_scanner_tab(self):
        """Crée l'onglet principal de scan"""
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="🔍 Scanner")
        
        # Frame de saisie
        input_frame = ttk.LabelFrame(scanner_frame, text="Configuration du Scan", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        # Saisie du domaine
        tk.Label(input_frame, text="Domaine à scanner:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', pady=5)
        self.domain_entry = ttk.Entry(input_frame, width=30, font=('Arial', 10))
        self.domain_entry.grid(row=0, column=1, padx=10, pady=5)
        self.domain_entry.bind('<Return>', lambda e: self.start_scan())
        
        # Options de scan
        options_frame = ttk.Frame(input_frame)
        options_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky='w')
        
        self.scan_subdomains_var = tk.BooleanVar(value=True)
        self.scan_ports_var = tk.BooleanVar(value=True)
        self.scan_http_var = tk.BooleanVar(value=True)
        self.generate_report_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Scanner les sous-domaines", 
                       variable=self.scan_subdomains_var).grid(row=0, column=0, sticky='w', padx=5)
        ttk.Checkbutton(options_frame, text="Scanner les ports", 
                       variable=self.scan_ports_var).grid(row=0, column=1, sticky='w', padx=5)
        ttk.Checkbutton(options_frame, text="Tester HTTP/HTTPS", 
                       variable=self.scan_http_var).grid(row=1, column=0, sticky='w', padx=5)
        ttk.Checkbutton(options_frame, text="Générer rapport", 
                       variable=self.generate_report_var).grid(row=1, column=1, sticky='w', padx=5)
        
        # Boutons de contrôle
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="🚀 Démarrer le Scan", 
                                     command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⏹️ Arrêter", 
                                     command=self.stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="🗑️ Effacer", 
                  command=self.clear_results).pack(side='left', padx=5)
        
        # Barre de progression
        self.progress_var = tk.StringVar(value="Prêt")
        self.progress_label = tk.Label(scanner_frame, textvariable=self.progress_var, 
                                      font=('Arial', 10), fg='#2c3e50')
        self.progress_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(scanner_frame, mode='indeterminate')
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        # Zone de résultats en temps réel
        results_frame = ttk.LabelFrame(scanner_frame, text="Résultats en Temps Réel", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20, 
                                                     font=('Consolas', 9),
                                                     bg='#34495e', fg='#ecf0f1',
                                                     insertbackground='white')
        self.results_text.pack(fill='both', expand=True)
        
        # Configuration des tags pour les couleurs
        self.results_text.tag_configure('success', foreground='#2ecc71')
        self.results_text.tag_configure('error', foreground='#e74c3c')
        self.results_text.tag_configure('warning', foreground='#f39c12')
        self.results_text.tag_configure('info', foreground='#3498db')
        self.results_text.tag_configure('highlight', foreground='#f1c40f')
        
    def create_results_tab(self):
        """Crée l'onglet des résultats détaillés"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Résultats")
        
        # Informations générales
        info_frame = ttk.LabelFrame(results_frame, text="Informations Générales", padding=10)
        info_frame.pack(fill='x', padx=10, pady=10)
        
        self.info_text = tk.Text(info_frame, height=6, font=('Arial', 10), 
                                bg='#ecf0f1', fg='#2c3e50')
        self.info_text.pack(fill='x')
        
        # PanedWindow pour diviser l'espace
        paned_window = ttk.PanedWindow(results_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)

        # Frame pour les ports et les sous-domaines
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=2)

        # Ports ouverts
        ports_frame = ttk.LabelFrame(left_frame, text="Ports Ouverts", padding=10)
        ports_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Treeview pour les ports
        self.ports_tree = ttk.Treeview(ports_frame, columns=('Port', 'Service', 'Version', 'Vulnérabilités', 'Bannière'),
                                      show='headings', height=6)
        self.ports_tree.heading('Port', text='Port')
        self.ports_tree.heading('Service', text='Service')
        self.ports_tree.heading('Version', text='Version')
        self.ports_tree.heading('Vulnérabilités', text='Vulnérabilités')
        self.ports_tree.heading('Bannière', text='Bannière')
        self.ports_tree.column('Port', width=60)
        self.ports_tree.column('Service', width=100)
        self.ports_tree.column('Version', width=100)
        self.ports_tree.column('Vulnérabilités', width=100)
        self.ports_tree.column('Bannière', width=140)
        self.ports_tree.pack(fill='both', expand=True)

        # Sous-domaines
        subdomains_frame = ttk.LabelFrame(left_frame, text="Sous-domaines Trouvés", padding=10)
        subdomains_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.subdomains_tree = ttk.Treeview(subdomains_frame, columns=('Domaine', 'IP'), 
                                           show='headings')
        self.subdomains_tree.heading('Domaine', text='Sous-domaine')
        self.subdomains_tree.heading('IP', text='Adresse IP')
        self.subdomains_tree.column('Domaine', width=300)
        self.subdomains_tree.column('IP', width=150)
        self.subdomains_tree.pack(fill='both', expand=True)

        # Frame pour le graphique
        self.graph_frame = ttk.LabelFrame(paned_window, text="Graphique des Ports", padding=10)
        paned_window.add(self.graph_frame, weight=1)
        
        # Boutons d'export
        export_frame = ttk.Frame(results_frame)
        export_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(export_frame, text="💾 Exporter JSON", 
                  command=self.export_json).pack(side='left', padx=5)
        ttk.Button(export_frame, text="📄 Exporter TXT", 
                  command=self.export_txt).pack(side='left', padx=5)
        ttk.Button(export_frame, text="📋 Copier dans le Presse-papier", 
                  command=self.copy_to_clipboard).pack(side='left', padx=5)
        ttk.Button(export_frame, text="📄 Exporter CSV",
                  command=self.export_csv).pack(side='left', padx=5)
        ttk.Button(export_frame, text="🌐 Exporter HTML",
                  command=self.export_html).pack(side='left', padx=5)
        
    def export_csv(self):
        """Exporte les résultats en CSV"""
        if not self.current_scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à exporter")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")],
            title="Exporter en CSV"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f)
                    
                    # En-têtes
                    writer.writerow(['Catégorie', 'Information', 'Détail'])
                    
                    results = self.current_scan_results
                    writer.writerow(['Domaine', results.get('domain', 'N/A'), ''])
                    writer.writerow(['Adresse IP', results.get('ip', 'N/A'), ''])
                    
                    if results.get('open_ports_details'):
                        writer.writerow(['--- PORTS OUVERTS ---', '', ''])
                        writer.writerow(['Port', 'Service', 'Version'])
                        for p in results['open_ports_details']:
                            writer.writerow([p['port'], p['service'], p['version']])
                    
                    if results.get('subdomains'):
                        writer.writerow(['--- SOUS-DOMAINES ---', '', ''])
                        writer.writerow(['Sous-domaine', 'Adresse IP', ''])
                        for sub, ip in results['subdomains']:
                            writer.writerow([sub, ip, ''])

                messagebox.showinfo("Succès", f"Résultats exportés vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export CSV: {str(e)}")

    def export_html(self):
        """Exporte les résultats en HTML"""
        if not self.current_scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à exporter")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Fichiers HTML", "*.html"), ("Tous les fichiers", "*.*")],
            title="Exporter en HTML"
        )

        if filename:
            try:
                results = self.current_scan_results
                html = "<html><head><title>Rapport de Scan</title>"
                html += "<style>body { font-family: sans-serif; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; } tr:nth-child(even) { background-color: #f2f2f2; } th { background-color: #4CAF50; color: white; }</style>"
                html += "</head><body>"
                html += f"<h1>Rapport de Scan pour {results.get('domain', 'N/A')}</h1>"
                
                if results.get('open_ports_details'):
                    html += "<h2>Ports Ouverts</h2><table><tr><th>Port</th><th>Service</th><th>Version</th></tr>"
                    for p in results['open_ports_details']:
                        html += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['version']}</td></tr>"
                    html += "</table>"

                if results.get('subdomains'):
                    html += "<h2>Sous-domaines</h2><table><tr><th>Sous-domaine</th><th>Adresse IP</th></tr>"
                    for sub, ip in results['subdomains']:
                        html += f"<tr><td>{sub}</td><td>{ip}</td></tr>"
                    html += "</table>"

                html += "</body></html>"

                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html)
                
                messagebox.showinfo("Succès", f"Rapport HTML exporté vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export HTML: {str(e)}")

    def create_history_tab(self):
        """Crée l'onglet historique des scans"""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="📈 Historique")
        
        # Liste des scans précédents
        self.history_tree = ttk.Treeview(history_frame, 
                                        columns=('Date', 'Domaine', 'IP', 'Ports', 'Statut'), 
                                        show='headings')
        self.history_tree.heading('Date', text='Date')
        self.history_tree.heading('Domaine', text='Domaine')
        self.history_tree.heading('IP', text='IP')
        self.history_tree.heading('Ports', text='Ports Ouverts')
        self.history_tree.heading('Statut', text='Statut')
        
        self.history_tree.column('Date', width=150)
        self.history_tree.column('Domaine', width=200)
        self.history_tree.column('IP', width=120)
        self.history_tree.column('Ports', width=100)
        self.history_tree.column('Statut', width=100)
        
        self.history_tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Boutons de gestion
        history_buttons = ttk.Frame(history_frame)
        history_buttons.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(history_buttons, text="🔄 Recharger", 
                  command=self.refresh_history).pack(side='left', padx=5)
        ttk.Button(history_buttons, text="🗑️ Effacer Historique", 
                  command=self.clear_history).pack(side='left', padx=5)
        ttk.Button(history_buttons, text="📊 Voir Détails", 
                  command=self.view_history_details).pack(side='left', padx=5)
        
    def create_network_tab(self):
        """Crée l'onglet du scanner de réseau"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="📡 Scanner Réseau")

        # Frame de contrôle
        network_control_frame = ttk.LabelFrame(network_frame, text="Contrôle du Scan Réseau", padding=10)
        network_control_frame.pack(fill='x', padx=10, pady=10)

        self.scan_network_button = ttk.Button(network_control_frame, text="🚀 Démarrer le Scan Réseau",
                                            command=self.start_network_scan, style='Accent.TButton')
        self.scan_network_button.pack(side='left', padx=5)

        self.stop_network_scan_button = ttk.Button(network_control_frame, text="⏹️ Arrêter",
                                                 command=self.stop_network_scan, state='disabled')
        self.stop_network_scan_button.pack(side='left', padx=5)

        tk.Label(network_control_frame, text="Plage IP (ex: 192.168.1.0/24):").pack(side='left', padx=(10, 0))
        self.ip_range_entry = ttk.Entry(network_control_frame, width=30)
        self.ip_range_entry.pack(side='left', padx=5)

        # Frame pour la liste des hôtes et les résultats de port scan
        network_results_frame = ttk.Frame(network_frame)
        network_results_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Liste des hôtes découverts
        hosts_frame = ttk.LabelFrame(network_results_frame, text="Hôtes Découverts", padding=10)
        hosts_frame.pack(side='left', fill='y', padx=5)

        self.hosts_tree = ttk.Treeview(hosts_frame, columns=('IP', 'Status'), show='headings', height=15)
        self.hosts_tree.heading('IP', text='Adresse IP')
        self.hosts_tree.heading('Status', text='Statut')
        self.hosts_tree.column('IP', width=150)
        self.hosts_tree.column('Status', width=100)
        self.hosts_tree.pack(fill='y', expand=True)
        self.hosts_tree.bind('<<TreeviewSelect>>', self.on_host_select)

        # Résultats du scan de ports pour l'hôte sélectionné
        ports_results_frame = ttk.LabelFrame(network_results_frame, text="Scan de Ports de l'Hôte", padding=10)
        ports_results_frame.pack(side='right', fill='both', expand=True, padx=5)

        self.host_ports_text = scrolledtext.ScrolledText(ports_results_frame, height=20,
                                                         font=('Consolas', 9),
                                                         bg='#34495e', fg='#ecf0f1',
                                                         insertbackground='white')
        self.host_ports_text.pack(fill='both', expand=True)

    def start_network_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_network_button.config(state='disabled')
        self.stop_network_scan_button.config(state='normal')
        self.status_var.set("Scan du réseau en cours...")
        self.progress_bar.start()

        for i in self.hosts_tree.get_children():
            self.hosts_tree.delete(i)
        self.host_ports_text.delete(1.0, 'end')

        ip_range = self.ip_range_entry.get().strip()
        self.network_scan_thread = threading.Thread(target=self.run_network_scan_thread, args=(ip_range,))
        self.network_scan_thread.daemon = True
        self.network_scan_thread.start()

    def stop_network_scan(self):
        self.scanning = False
        self.scan_network_button.config(state='normal')
        self.stop_network_scan_button.config(state='disabled')
        self.status_var.set("Scan du réseau arrêté.")
        self.progress_bar.stop()

    def run_network_scan_thread(self, ip_range=None):
        network_to_scan = ip_range
        if not network_to_scan:
            _, _, network_to_scan = self.get_local_ip_and_network()
        
        if not network_to_scan:
            self.status_var.set("Erreur: Impossible de déterminer le réseau local.")
            self.stop_network_scan()
            return

        try:
            network = ipaddress.ip_network(network_to_scan, strict=False)
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in network.hosts()}
                
                for future in future_to_ip:
                    if not self.scanning:
                        break
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            self.hosts_tree.insert('', 'end', values=(str(ip), 'Actif'))
                    except Exception:
                        pass
        except Exception as e:
            self.status_var.set(f"Erreur lors du scan réseau: {e}")
        
        if self.scanning:
            self.status_var.set("Scan du réseau terminé.")
        self.stop_network_scan()

    def get_local_ip_and_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            if os.name == 'nt':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                match = re.search(r'Subnet Mask[\. ]*: ([\d\.]+)', result.stdout)
                if not match:
                    match = re.search(r'Masque de sous-réseau[\. ]*: ([\d\.]+)', result.stdout)
                
                if match:
                    subnet_mask = match.group(1)
                    network = ipaddress.ip_network(f'{local_ip}/{subnet_mask}', strict=False)
                    return str(network.network_address), str(network.netmask), str(network)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                match = re.search(r'netmask ([\d\.]+)', result.stdout)
                if match:
                    subnet_mask = match.group(1)
                    network = ipaddress.ip_network(f'{local_ip}/{subnet_mask}', strict=False)
                    return str(network.network_address), str(network.netmask), str(network)

            return local_ip, "255.255.255.0", f"{local_ip}/24"
        except Exception as e:
            self.status_var.set(f"Erreur IP locale: {e}")
            return None, None, None

    def ping_host(self, ip):
        try:
            if os.name == 'nt':
                result = subprocess.run(['ping', '-n', '1', '-w', '500', str(ip)], capture_output=True, text=True, timeout=1)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '0.5', str(ip)], capture_output=True, text=True, timeout=1)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def on_host_select(self, event):
        selection = self.hosts_tree.selection()
        if not selection:
            return
        
        item = self.hosts_tree.item(selection[0])
        ip_address = item['values'][0]
        
        self.host_ports_text.delete(1.0, 'end')
        self.host_ports_text.insert('end', f"Scan des ports pour {ip_address}...\n")
        
        # Run port scan in a new thread
        scan_thread = threading.Thread(target=self.scan_selected_host_ports, args=(ip_address,))
        scan_thread.daemon = True
        scan_thread.start()

    def scan_selected_host_ports(self, ip):
        self.host_ports_text.delete(1.0, 'end')
        self.host_ports_text.insert('end', f"Scan des ports pour {ip}...\n")
        
        open_ports_details = self.scan_ports(ip)
        
        if open_ports_details:
            self.host_ports_text.insert('end', "Ports ouverts:\n", 'success')
            for details in open_ports_details:
                service = details['service']
                version = details['version']
                self.host_ports_text.insert('end', f"  - Port {details['port']}: {service} ({version})\n")
        else:
            self.host_ports_text.insert('end', "Aucun port ouvert trouvé.\n", 'warning')

    def create_config_tab(self):
        """Crée l'onglet de configuration"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="⚙️ Configuration")
        
        # Configuration des ports
        ports_config_frame = ttk.LabelFrame(config_frame, text="Ports à Scanner", padding=10)
        ports_config_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(ports_config_frame, text="Ports (séparés par des virgules):").pack(anchor='w')
        self.ports_entry = ttk.Entry(ports_config_frame, width=50)
        self.ports_entry.pack(fill='x', pady=5)
        self.ports_entry.insert(0, ','.join(map(str, self.ports_to_scan)))
        
        # Configuration des sous-domaines
        subdomains_config_frame = ttk.LabelFrame(config_frame, text="Sous-domaines à Tester", padding=10)
        subdomains_config_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(subdomains_config_frame, text="Sous-domaines (séparés par des virgules):").pack(anchor='w')
        self.subdomains_entry = ttk.Entry(subdomains_config_frame, width=50)
        self.subdomains_entry.pack(fill='x', pady=5)
        self.subdomains_entry.insert(0, ','.join(self.common_subdomains))
        
        # Configuration des timeouts
        timeout_config_frame = ttk.LabelFrame(config_frame, text="Timeouts", padding=10)
        timeout_config_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(timeout_config_frame, text="Timeout de connexion (secondes):").pack(anchor='w')
        self.timeout_var = tk.IntVar(value=self.timeout)
        timeout_spinbox = ttk.Spinbox(timeout_config_frame, from_=1, to=30, 
                                     textvariable=self.timeout_var, width=10)
        timeout_spinbox.pack(anchor='w', pady=5)

        # Configuration de l'API VulDB
        vulndb_api_frame = ttk.LabelFrame(config_frame, text="API VulDB", padding=10)
        vulndb_api_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(vulndb_api_frame, text="Clé d'API VulDB:").pack(anchor='w')
        self.vulndb_api_key_entry = ttk.Entry(vulndb_api_frame, width=50, show="*")
        self.vulndb_api_key_entry.pack(fill='x', pady=5)
        self.vulndb_api_key_entry.insert(0, self.vulndb_api_key)
        
        # Boutons de configuration
        config_buttons = ttk.Frame(config_frame)
        config_buttons.pack(fill='x', padx=10, pady=20)
        
        tk.Button(config_buttons, text="💾 Sauvegarder Configuration", 
                  command=self.save_config, fg="white", bg="#3498db", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        tk.Button(config_buttons, text="🔄 Réinitialiser", 
                  command=self.reset_config, fg="white", bg="#3498db", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        tk.Button(config_buttons, text="Ports Courants", 
                  command=self.set_common_ports, fg="white", bg="#3498db", font=('Arial', 10, 'bold')).pack(side='left', padx=5)
        
    def set_common_ports(self):
        """Remplit le champ des ports avec les ports les plus courants."""
        common_ports = self.get_common_ports()
        self.ports_entry.delete(0, 'end')
        self.ports_entry.insert(0, ','.join(map(str, common_ports)))

    def get_common_ports(self):
        """Retourne une liste des ports les plus courants."""
        # Source: Nmap top-ports.
        return [
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 
            113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 
            513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 
            995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 
            2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 
            5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 
            6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 
            10000
        ]

    def create_status_bar(self):
        """Crée la barre de statut"""
        self.status_frame = tk.Frame(self.root, relief='sunken', bd=1, bg='#34495e')
        self.status_frame.pack(fill='x', side='bottom')
        
        self.status_var = tk.StringVar(value="Prêt")
        self.status_label = tk.Label(self.status_frame, textvariable=self.status_var, 
                                    bg='#34495e', fg='#ecf0f1', anchor='w')
        self.status_label.pack(side='left', padx=5)
        
        # Horloge
        self.clock_label = tk.Label(self.status_frame, bg='#34495e', fg='#ecf0f1')
        self.clock_label.pack(side='right', padx=5)
        self.update_clock()
        
    def update_clock(self):
        """Met à jour l'horloge"""
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.clock_label.config(text=current_time)
        self.root.after(1000, self.update_clock)
        
    def log_message(self, message, tag='info'):
        """Ajoute un message dans la zone de résultats"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        
        self.results_text.insert('end', full_message, tag)
        self.results_text.see('end')
        self.root.update_idletasks()
        
    def start_scan(self):
        """Démarre le scan en arrière-plan"""
        if self.scanning:
            return
            
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Erreur", "Veuillez entrer un domaine à scanner")
            return
            
        if not self.is_valid_domain(domain):
            messagebox.showerror("Erreur", "Format de domaine invalide")
            return
            
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_bar.start()
        self.progress_var.set("Scan en cours...")
        self.status_var.set(f"Scan de {domain} en cours...")
        
        # Clear previous results
        self.results_text.delete(1.0, 'end')
        self.clear_results_display()
        
        # Lancement du scan dans un thread séparé
        self.scan_thread = threading.Thread(target=self.run_scan, args=(domain,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def stop_scan(self):
        """Arrête le scan en cours"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_bar.stop()
        self.progress_var.set("Scan arrêté")
        self.status_var.set("Scan arrêté par l'utilisateur")
        self.log_message("Scan arrêté par l'utilisateur", 'warning')
        
    def run_scan(self, domain):
        """Exécute le scan complet"""
        try:
            self.log_message(f"Début du scan de {domain}", 'info')
            
            scan_results = {
                'domain': domain,
                'timestamp': datetime.datetime.now().isoformat(),
                'status': 'En cours'
            }
            
            # 1. Résolution DNS
            if not self.scanning:
                return
            self.log_message("Résolution DNS...", 'info')
            ip = self.resolve_domain(domain)
            if not ip:
                scan_results['status'] = 'Échec - DNS'
                self.finish_scan(scan_results)
                return
            scan_results['ip'] = ip
            
            # 2. Tests de connectivité
            if not self.scanning:
                return
            self.log_message("Test de connectivité...", 'info')
            ping_rate, ping_time = self.ping_domain(domain)
            scan_results['ping_success_rate'] = ping_rate
            scan_results['ping_avg_time'] = ping_time
            
            # 3. Analyse TTL
            if not self.scanning:
                return
            self.log_message("Analyse du système...", 'info')
            ttl, os_guess = self.analyze_ttl(domain)
            scan_results['ttl'] = ttl
            scan_results['os_guess'] = os_guess
            
            # 4. Reverse DNS
            if not self.scanning:
                return
            self.log_message("Résolution DNS inverse...", 'info')
            reverse_dns = self.reverse_dns(ip)
            scan_results['reverse_dns'] = reverse_dns
            
            # 5. Scan des ports
            if self.scan_ports_var.get() and self.scanning:
                self.log_message("Scan des ports...", 'info')
                open_ports_details = self.scan_ports(ip)
                scan_results['open_ports_details'] = open_ports_details
            
            # 6. Tests HTTP/HTTPS
            if self.scan_http_var.get() and self.scanning:
                self.log_message("Test des services web...", 'info')
                http_success, http_status = self.http_request(domain, ip)
                https_available = self.check_https(ip)
                scan_results['http_status'] = http_status
                scan_results['https_available'] = https_available
            
            # 7. Scan des sous-domaines
            if self.scan_subdomains_var.get() and self.scanning:
                self.log_message("Scan des sous-domaines...", 'info')
                subdomains = self.scan_subdomains(domain)
                scan_results['subdomains'] = subdomains
            
            if self.scanning:
                scan_results['status'] = 'Terminé'
                self.finish_scan(scan_results)
                
        except Exception as e:
            self.log_message(f"Erreur lors du scan: {str(e)}", 'error')
            scan_results['status'] = 'Erreur'
            scan_results['error'] = str(e)
            self.finish_scan(scan_results)
            
    def finish_scan(self, scan_results):
        """Termine le scan et met à jour l'interface"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_bar.stop()
        
        self.current_scan_results = scan_results
        self.scan_history.append(scan_results)
        
        # Mise à jour des résultats
        self.update_results_display(scan_results)
        self.update_graph(scan_results)
        
        # Génération du rapport si demandé
        if self.generate_report_var.get():
            self.generate_report(scan_results)
            
        completion_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.progress_var.set(f"Scan terminé à {completion_time}")
        self.status_var.set(f"Scan de {scan_results['domain']} terminé - Statut: {scan_results['status']}")
        
        self.log_message(f"Scan terminé - Statut: {scan_results['status']}", 'success')
        
    def update_graph(self, results):
        """Met à jour le graphique des résultats."""
        # Nettoyer le frame précédent
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        if not results.get('open_ports_details'):
            return

        open_ports = len(results.get('open_ports_details', []))
        total_ports = len(self.ports_to_scan)
        closed_ports = total_ports - open_ports

        labels = 'Ports Ouverts', 'Ports Fermés'
        sizes = [open_ports, closed_ports]
        colors = ['#2ecc71', '#e74c3c']
        explode = (0.1, 0)  # explode 1st slice

        fig = Figure(figsize=(4, 3), dpi=100)
        ax = fig.add_subplot(111)
        ax.pie(sizes, explode=explode, labels=labels, colors=colors,
               autopct='%1.1f%%', shadow=True, startangle=140)
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    def update_results_display(self, results):
        """Met à jour l'affichage des résultats"""
        # Informations générales
        info_text = f"Domaine: {results['domain']}\n"
        info_text += f"Adresse IP: {results.get('ip', 'N/A')}\n"
        info_text += f"Date du scan: {results['timestamp']}\n"
        info_text += f"Statut: {results['status']}\n"
        if results.get('reverse_dns'):
            info_text += f"Nom de machine: {results['reverse_dns']}\n"
        if results.get('os_guess'):
            info_text += f"Système probable: {results['os_guess']}\n"
            
        self.info_text.delete(1.0, 'end')
        self.info_text.insert('end', info_text)
        
        # Ports ouverts
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
            
        if results.get('open_ports_details'):
            for details in results['open_ports_details']:
                port = details['port']
                service = details['service']
                version = details['version']
                banner = details.get('banner', 'N/A')
                if banner and len(banner) > 50:
                    banner = banner[:50] + '...'
                vulns = details.get('vulns', 'N/A')
                self.ports_tree.insert('', 'end', values=(port, service, version, vulns, banner))
        
        # Sous-domaines
        for item in self.subdomains_tree.get_children():
            self.subdomains_tree.delete(item)
            
        if results.get('subdomains'):
            for subdomain, ip in results['subdomains']:
                self.subdomains_tree.insert('', 'end', values=(subdomain, ip))
        
        # Mise à jour de l'historique
        self.refresh_history()
        
    def clear_results_display(self):
        """Efface l'affichage des résultats"""
        self.info_text.delete(1.0, 'end')
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        for item in self.subdomains_tree.get_children():
            self.subdomains_tree.delete(item)
            
    def clear_results(self):
        """Efface tous les résultats"""
        self.results_text.delete(1.0, 'end')
        self.clear_results_display()
        self.progress_var.set("Prêt")
        self.status_var.set("Prêt")
        
    def refresh_history(self):
        """Actualise l'affichage de l'historique"""
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        for scan in self.scan_history:
            date = datetime.datetime.fromisoformat(scan['timestamp']).strftime("%Y-%m-%d %H:%M")
            domain = scan['domain']
            ip = scan.get('ip', 'N/A')
            ports_count = len(scan.get('open_ports', []))
            status = scan['status']
            
            self.history_tree.insert('', 'end', values=(date, domain, ip, ports_count, status))
            
    def view_history_details(self):
        """Affiche les détails d'un scan de l'historique"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner un scan dans l'historique")
            return
            
        item = self.history_tree.item(selection[0])
        index = self.history_tree.index(selection[0])
        
        if index < len(self.scan_history):
            scan_data = self.scan_history[index]
            self.show_scan_details(scan_data)
            
    def show_scan_details(self, scan_data):
        """Affiche les détails d'un scan dans une nouvelle fenêtre"""
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Détails du scan - {scan_data['domain']}")
        details_window.geometry("800x600")
        
        text_widget = scrolledtext.ScrolledText(details_window, font=('Consolas', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        details_text = self.format_scan_details(scan_data)
        text_widget.insert('end', details_text)
        text_widget.config(state='disabled')
        
    def format_scan_details(self, scan_data):
        """Formate les détails d'un scan pour l'affichage"""
        details = f"DÉTAILS DU SCAN\n{'='*50}\n\n"
        details += f"Domaine: {scan_data['domain']}\n"
        details += f"Date: {scan_data['timestamp']}\n"
        details += f"Statut: {scan_data['status']}\n\n"
        
        if scan_data.get('ip'):
            details += f"INFORMATIONS RÉSEAU\n{'-'*30}\n"
            details += f"Adresse IP: {scan_data['ip']}\n"
            if scan_data.get('reverse_dns'):
                details += f"Nom de machine: {scan_data['reverse_dns']}\n"
            if scan_data.get('ping_success_rate'):
                details += f"Ping réussite: {scan_data['ping_success_rate']:.1f}%\n"
            if scan_data.get('os_guess'):
                details += f"Système: {scan_data['os_guess']}\n"
            details += "\n"
        
        if scan_data.get('open_ports_details'):
            details += f"PORTS OUVERTS\n{'-'*30}\n"
            for port_details in scan_data['open_ports_details']:
                details += f"Port {port_details['port']}: {port_details['service']} ({port_details['version']})\n"
                if port_details.get('banner'):
                    details += f"  Bannière: {port_details['banner'][:100]}...\n"
            details += "\n"
        
        if scan_data.get('subdomains'):
            details += f"SOUS-DOMAINES\n{'-'*30}\n"
            for subdomain, ip in scan_data['subdomains']:
                details += f"{subdomain} -> {ip}\n"
            details += "\n"
        
        return details
        
    def get_service_name(self, port):
        """Retourne le nom du service associé au port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis'
        }
        return services.get(port, 'Inconnu')
    
    def export_json(self):
        """Exporte les résultats en JSON"""
        if not self.current_scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à exporter")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Fichiers JSON", "*.json"), ("Tous les fichiers", "*.*")],
            title="Exporter en JSON"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.current_scan_results, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Succès", f"Résultats exportés vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export: {str(e)}")
    
    def export_txt(self):
        """Exporte les résultats en TXT"""
        if not self.current_scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à exporter")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")],
            title="Exporter en TXT"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.format_scan_details(self.current_scan_results))
                messagebox.showinfo("Succès", f"Rapport exporté vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'export: {str(e)}")
    
    def copy_to_clipboard(self):
        """Copie les résultats dans le presse-papier"""
        if not self.current_scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à copier")
            return
            
        details = self.format_scan_details(self.current_scan_results)
        self.root.clipboard_clear()
        self.root.clipboard_append(details)
        messagebox.showinfo("Succès", "Résultats copiés dans le presse-papier")
    
    def clear_history(self):
        """Efface l'historique des scans"""
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment effacer l'historique?"):
            self.scan_history.clear()
            self.refresh_history()
            messagebox.showinfo("Succès", "Historique effacé")
    
    def load_config(self):
        """Charge la configuration depuis config.json"""
        try:
            with open("config.json", 'r') as f:
                config = json.load(f)
                self.ports_to_scan = config.get('ports_to_scan', self.ports_to_scan)
                self.common_subdomains = config.get('common_subdomains', self.common_subdomains)
                self.timeout = config.get('timeout', self.timeout)
                self.vulndb_api_key = config.get('vulndb_api_key', '')
        except (FileNotFoundError, json.JSONDecodeError):
            # Le fichier n'existe pas ou est invalide, on utilise la configuration par défaut
            pass

    def save_config(self):
        """Sauvegarde la configuration"""
        try:
            # Mise à jour des ports
            ports_text = self.ports_entry.get().strip()
            if ports_text:
                self.ports_to_scan = [int(p.strip()) for p in ports_text.split(',') if p.strip().isdigit()]
            
            # Mise à jour des sous-domaines
            subdomains_text = self.subdomains_entry.get().strip()
            if subdomains_text:
                self.common_subdomains = [s.strip() for s in subdomains_text.split(',') if s.strip()]
            
            # Mise à jour du timeout
            self.timeout = self.timeout_var.get()

            # Sauvegarde dans le fichier
            self.vulndb_api_key = self.vulndb_api_key_entry.get().strip()
            config_data = {
                'ports_to_scan': self.ports_to_scan,
                'common_subdomains': self.common_subdomains,
                'timeout': self.timeout,
                'vulndb_api_key': self.vulndb_api_key
            }
            with open("config.json", 'w') as f:
                json.dump(config_data, f, indent=2)

            messagebox.showinfo("Succès", "Configuration sauvegardée dans config.json")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la sauvegarde: {str(e)}")
    
    def reset_config(self):
        """Remet la configuration par défaut"""
        self.ports_to_scan = [22, 80, 443, 3306, 21, 25, 53, 110, 993, 995]
        self.common_subdomains = ['www', 'mail', 'admin', 'ftp', 'ssh', 'dev', 'test', 'blog', 'shop', 'api']
        self.timeout = 5
        
        self.ports_entry.delete(0, 'end')
        self.ports_entry.insert(0, ','.join(map(str, self.ports_to_scan)))
        
        self.subdomains_entry.delete(0, 'end')
        self.subdomains_entry.insert(0, ','.join(self.common_subdomains))
        
        self.timeout_var.set(self.timeout)
        self.vulndb_api_key = ""
        self.vulndb_api_key_entry.delete(0, 'end')
        
        # Supprimer le fichier de configuration s'il existe
        if os.path.exists("config.json"):
            os.remove("config.json")

        messagebox.showinfo("Succès", "Configuration réinitialisée")
    
    def generate_report(self, scan_results):
        """Génère un rapport de scan"""
        try:
            domain = scan_results['domain'].replace('.', '_')
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"rapport_{domain}_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.format_scan_details(scan_results))
            
            self.log_message(f"Rapport généré: {filename}", 'success')
            
        except Exception as e:
            self.log_message(f"Erreur lors de la génération du rapport: {str(e)}", 'error')
    
    # Méthodes du scanner original adaptées
    def is_valid_domain(self, domain):
        """Vérifie si le domaine est valide"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(domain)) and len(domain) <= 253
    
    def resolve_domain(self, domain):
        """Résout l'adresse IP d'un domaine"""
        try:
            ip = socket.gethostbyname(domain)
            self.log_message(f"DNS: {domain} -> {ip}", 'success')
            return ip
        except socket.gaierror:
            self.log_message(f"Erreur DNS: Impossible de résoudre {domain}", 'error')
            return None
    
    def ping_domain(self, domain):
        """Ping le domaine et calcule les statistiques"""
        success_count = 0
        ping_times = []
        
        for i in range(3):
            if not self.scanning:
                break
                
            try:
                if os.name == 'nt':
                    result = subprocess.run(['ping', '-n', '1', '-w', '3000', domain], 
                                          capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '3', domain], 
                                          capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    success_count += 1
                    if os.name == 'nt':
                        match = re.search(r'temps[<=](\d+)ms', result.stdout)
                    else:
                        match = re.search(r'time=(\d+\.?\d*)', result.stdout)
                    
                    if match:
                        ping_times.append(float(match.group(1)))
                    
                    self.log_message(f"Ping {i+1}: SUCCESS", 'success')
                else:
                    self.log_message(f"Ping {i+1}: FAILED", 'error')
                    
            except subprocess.TimeoutExpired:
                self.log_message(f"Ping {i+1}: TIMEOUT", 'warning')
            except Exception:
                self.log_message(f"Ping {i+1}: ERROR", 'error')
        
        success_rate = (success_count / 3) * 100
        avg_time = sum(ping_times) / len(ping_times) if ping_times else 0
        
        self.log_message(f"Ping réussite: {success_rate:.1f}%", 'info')
        if avg_time > 0:
            self.log_message(f"Temps moyen: {avg_time:.1f}ms", 'info')
        
        return success_rate, avg_time
    
    def analyze_ttl(self, domain):
        """Analyse le TTL pour deviner le système d'exploitation"""
        try:
            if os.name == 'nt':
                result = subprocess.run(['ping', '-n', '1', domain], 
                                      capture_output=True, text=True, timeout=5)
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:
                result = subprocess.run(['ping', '-c', '1', domain], 
                                      capture_output=True, text=True, timeout=5)
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                if ttl <= 64:
                    os_guess = "Linux/Unix" if ttl > 32 else "Ancien système Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl <= 255:
                    os_guess = "Cisco/Routeur"
                else:
                    os_guess = "Système inconnu"
                
                self.log_message(f"TTL: {ttl} -> {os_guess}", 'info')
                return ttl, os_guess
            else:
                self.log_message("TTL non détecté", 'warning')
                return None, "Inconnu"
                
        except Exception as e:
            self.log_message(f"Erreur analyse TTL: {str(e)}", 'error')
            return None, "Erreur"
    
    def reverse_dns(self, ip):
        """Effectue une résolution DNS inverse"""
        try:
            hostname = socket.gethostbyaddr(ip)
            self.log_message(f"DNS inverse: {ip} -> {hostname[0]}", 'success')
            return hostname[0]
        except socket.herror:
            self.log_message(f"Pas de nom de machine pour {ip}", 'warning')
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
        """Tente de récupérer la bannière et d'identifier le service/version."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Probes spécifiques pour certains ports
            if port == 80:
                sock.send(b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            elif port == 21: # FTP
                pass # Le serveur FTP envoie souvent une bannière à la connexion
            elif port == 22: # SSH
                pass # Le serveur SSH envoie sa version
            elif port == 25: # SMTP
                pass # Le serveur SMTP envoie une bannière
            elif port == 443: # HTTPS
                # Pour HTTPS, une simple connexion ne suffit pas pour la bannière.
                # On pourrait utiliser ssl, mais pour l'instant on se contente de la connexion.
                return "SSL/TLS", "N/A", "Connexion SSL/TLS réussie"

            banner_bytes = sock.recv(2048)
            sock.close()
            
            banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            
            service, version = self.parse_banner(banner, port)
            
            return service, version, banner
        except Exception:
            return "Inconnu", "N/A", ""

    def parse_banner(self, banner, port):
        """Analyse une bannière pour en extraire le service et la version."""
        # Expressions régulières pour des services courants
        ssh_match = re.search(r'SSH-([\d\.]+)-([\w\d\._-]+)', banner)
        ftp_match = re.search(r'FTP server \((\w+)\s*([\d\.]+)\)', banner, re.IGNORECASE)
        smtp_match = re.search(r'ESMTP ([\w\d\.-]+)', banner)
        http_server_match = re.search(r'Server: ([\w\d\.\-\/]+)', banner, re.IGNORECASE)

        if ssh_match:
            return "SSH", ssh_match.group(2)
        if ftp_match:
            return f"FTP ({ftp_match.group(1)})", ftp_match.group(2)
        if smtp_match:
            return "SMTP", smtp_match.group(1)
        if http_server_match:
            return "HTTP", http_server_match.group(1)
        
        # Si aucune correspondance, on utilise le nom de service par défaut
        return self.get_service_name(port), "N/A"
    
    def check_vulnerabilities(self, service, version):
        """Interroge l'API VulDB pour les vulnérabilités."""
        if not self.vulndb_api_key:
            return "Clé API manquante"
        if version == "N/A":
            return "Version inconnue"

        try:
            # Formatage simple du nom du service pour la recherche
            product = service.split(' ')[0].lower()

            response = requests.post(
                'https://vuldb.com/?api',
                data={
                    'apikey': self.vulndb_api_key,
                    'search': f'{product}:{version}'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response', {}).get('status') == '200':
                    count = result.get('result_count', 0)
                    return f"{count} trouvée(s)"
                else:
                    return "Erreur API"
            else:
                return "Erreur HTTP"
        except requests.RequestException:
            return "Erreur réseau"

    def scan_ports(self, ip):
        """Scanne les ports configurés et récupère les bannières."""
        open_ports_details = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in self.ports_to_scan}
            
            for future in future_to_port:
                if not self.scanning: break
                port = future_to_port[future]
                try:
                    if future.result():
                        self.log_message(f"Port {port}: OUVERT", 'success')
                        service, version, banner = self.get_banner(ip, port)
                        
                        vuln_status = self.check_vulnerabilities(service, version)
                        port_details = {
                            'port': port,
                            'service': service,
                            'version': version,
                            'banner': banner,
                            'vulns': vuln_status
                        }
                        open_ports_details.append(port_details)
                        
                        log_msg = f"  Service: {service}"
                        if version != "N/A":
                            log_msg += f" - Version: {version}"
                        self.log_message(log_msg, 'highlight')
                        if banner:
                            self.log_message(f"  Bannière: {banner[:70]}...", 'info')
                    else:
                        # Optionnel: logger les ports fermés si besoin
                        # self.log_message(f"Port {port}: FERMÉ", 'error')
                        pass
                except Exception as e:
                    self.log_message(f"Erreur scan port {port}: {e}", 'error')

        return open_ports_details
    
    def http_request(self, domain, ip):
        """Effectue une requête HTTP"""
        try:
            if self.scan_port(ip, 80):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, 80))
                
                request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: CyberScanPro-GUI/1.0\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                if response:
                    status_line = response.split('\n')[0]
                    self.log_message(f"HTTP: {status_line.strip()}", 'success')
                    return True, status_line.strip()
                else:
                    self.log_message("HTTP: Aucune réponse", 'warning')
                    return False, None
            else:
                self.log_message("HTTP: Port 80 fermé", 'warning')
                return False, None
                
        except Exception as e:
            self.log_message(f"Erreur HTTP: {str(e)}", 'error')
            return False, None
    
    def check_https(self, ip):
        """Vérifie la disponibilité HTTPS"""
        if self.scan_port(ip, 443):
            self.log_message("HTTPS: DISPONIBLE", 'success')
            return True
        else:
            self.log_message("HTTPS: NON DISPONIBLE", 'warning')
            return False
    
    def scan_subdomains(self, domain):
        """Scanne les sous-domaines"""
        found_subdomains = []
        
        for subdomain in self.common_subdomains:
            if not self.scanning:
                break
                
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                self.log_message(f"Sous-domaine: {full_domain} -> {ip}", 'success')
                found_subdomains.append((full_domain, ip))
            except socket.gaierror:
                self.log_message(f"Sous-domaine: {full_domain} NON TROUVÉ", 'error')
        
        return found_subdomains
    
    def run(self):
        """Lance l'application GUI"""
        self.root.mainloop()

# Lancement de l'application
if __name__ == "__main__":
    app = CyberScanProGUI()
    app.run()