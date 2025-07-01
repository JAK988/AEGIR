import httpx
import asyncio
import socket
import time
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class PortResult:
    """Résultat d'un scan de port."""
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    response_time: float = 0.0
    status_code: int = 0
    title: str = ""
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

class PortScanner:
    """Scanner de ports professionnel avec gestion des timeouts et rate limiting."""
    
    def __init__(self, max_workers: int = 50, timeout: float = 5.0, rate_limit: float = 0.1):
        """
        Initialise le scanner de ports.
        Args:
            max_workers (int): Nombre de threads concurrents
            timeout (float): Timeout par port
            rate_limit (float): Délai entre chaque scan
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.rate_limit = rate_limit
        
        # Ports courants à scanner
        self.common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 8080: "http-proxy", 8443: "https-alt", 3306: "mysql",
            5432: "postgresql", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch",
            11211: "memcached", 3389: "rdp", 5900: "vnc", 5901: "vnc-1",
            5902: "vnc-2", 5903: "vnc-3", 5904: "vnc-4", 5905: "vnc-5",
            5906: "vnc-6", 5907: "vnc-7", 5908: "vnc-8", 5909: "vnc-9",
            5984: "couchdb", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch",
            11211: "memcached", 1433: "mssql", 1521: "oracle", 5432: "postgresql",
            3306: "mysql", 389: "ldap", 636: "ldaps", 389: "ldap", 636: "ldaps"
        }
        
        # Ports web pour fingerprinting avancé
        self.web_ports = {80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000}
        
    async def scan_web_port(self, host: str, port: int) -> PortResult:
        """
        Scan d'un port web avec httpx pour récupérer headers, title, etc.
        
        Args:
            host: Hôte cible
            port: Port à scanner
        
        Returns:
            PortResult: Résultat du scan
        """
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{host}:{port}"
        
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                response_time = time.time() - start_time
                
                # Extraire le titre
                title = ""
                if "text/html" in response.headers.get("content-type", ""):
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag:
                            title = title_tag.get_text().strip()
                    except Exception:
                        pass
                
                return PortResult(
                    port=port,
                    is_open=True,
                    service="http" if port in [80, 8080] else "https",
                    status_code=response.status_code,
                    title=title,
                    response_time=response_time,
                    headers=dict(response.headers)
                )
                
        except Exception:
            return PortResult(port=port, is_open=False)
    
    def scan_tcp_port(self, host: str, port: int) -> PortResult:
        """
        Scan TCP classique d'un port.
        
        Args:
            host: Hôte cible
            port: Port à scanner
        
        Returns:
            PortResult: Résultat du scan
        """
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            sock.close()
            
            if result == 0:
                service = self.common_ports.get(port, "unknown")
                return PortResult(
                    port=port,
                    is_open=True,
                    service=service,
                    response_time=response_time
                )
            else:
                return PortResult(port=port, is_open=False)
                
        except Exception:
            return PortResult(port=port, is_open=False)
    
    async def scan_host_ports(self, host: str, ports: Optional[List[int]] = None) -> Dict[int, PortResult]:
        """
        Scan complet des ports d'un hôte.
        
        Args:
            host: Hôte ou IP cible
            ports: Liste des ports à scanner (utilise les ports courants si None)
        
        Returns:
            Dict[int, PortResult]: Résultats du scan par port
        """
        if ports is None:
            ports = list(self.common_ports.keys())
        
        results = {}
        
        # Séparer les ports web des autres
        web_ports = [p for p in ports if p in self.web_ports]
        other_ports = [p for p in ports if p not in self.web_ports]
        
        # Scan des ports web en async
        if web_ports:
            web_tasks = [self.scan_web_port(host, port) for port in web_ports]
            web_results = await asyncio.gather(*web_tasks, return_exceptions=True)
            
            for i, result in enumerate(web_results):
                if isinstance(result, PortResult):
                    port = web_ports[i]
                    results[port] = result
        
        # Scan des autres ports en thread pool
        if other_ports:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {
                    executor.submit(self.scan_tcp_port, host, port): port 
                    for port in other_ports
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        results[port] = result
                    except Exception:
                        results[port] = PortResult(port=port, is_open=False)
        
        return results
    
    async def scan_multiple_hosts(self, hosts: List[str], ports: Optional[List[int]] = None) -> Dict[str, Dict[int, PortResult]]:
        """
        Scan de plusieurs hôtes en parallèle.
        
        Args:
            hosts: Liste des hôtes à scanner
            ports: Liste des ports à scanner
        
        Returns:
            Dict[str, Dict[int, PortResult]]: Résultats par hôte
        """
        all_results = {}
        
        # Limiter la concurrence pour éviter la surcharge
        semaphore = asyncio.Semaphore(10)
        
        async def scan_with_semaphore(host):
            async with semaphore:
                return host, await self.scan_host_ports(host, ports)
        
        tasks = [scan_with_semaphore(host) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple):
                host, host_results = result
                all_results[host] = host_results
        
        return all_results

# Fonction utilitaire pour usage simple
async def quick_port_scan(host: str, ports: Optional[List[int]] = None) -> Dict[int, PortResult]:
    """
    Scan rapide des ports d'un hôte.
    
    Args:
        host: Hôte cible
        ports: Liste des ports à scanner
    
    Returns:
        Dict[int, PortResult]: Résultats du scan
    """
    scanner = PortScanner()
    return await scanner.scan_host_ports(host, ports)

if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python3 port_scanner.py <host> [port1,port2,...]")
            sys.exit(1)
        
        host = sys.argv[1]
        ports = None
        
        if len(sys.argv) > 2:
            ports = [int(p) for p in sys.argv[2].split(',')]
        
        print(f"[+] Scanning {host}...")
        results = await quick_port_scan(host, ports)
        
        open_ports = [port for port, result in results.items() if result.is_open]
        print(f"\n[+] Open ports: {open_ports}")
        
        for port, result in results.items():
            if result.is_open:
                print(f"  {port}/tcp - {result.service}")
                if result.title:
                    print(f"    Title: {result.title}")
                if result.status_code:
                    print(f"    Status: {result.status_code}")
    
    asyncio.run(main()) 