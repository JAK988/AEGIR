import asyncio
import base64
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from playwright.async_api import async_playwright, Browser, Page

@dataclass
class ScreenshotResult:
    """Résultat d'une capture d'écran."""
    url: str
    success: bool
    screenshot_path: str = ""
    error_message: str = ""
    page_title: str = ""
    viewport_size: Tuple[int, int] = (1920, 1080)
    load_time: float = 0.0

class ScreenshotCapture:
    """Capture d'écrans automatique avec Playwright."""
    
    def __init__(self, 
                 screenshot_dir: str = "screenshots",
                 viewport_width: int = 1920,
                 viewport_height: int = 1080,
                 timeout: int = 30000):
        """
        Initialise le capteur d'écrans.
        
        Args:
            screenshot_dir: Répertoire de sauvegarde des screenshots
            viewport_width: Largeur de la fenêtre
            viewport_height: Hauteur de la fenêtre
            timeout: Timeout en millisecondes
        """
        self.screenshot_dir = Path(screenshot_dir)
        self.screenshot_dir.mkdir(exist_ok=True)
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.timeout = timeout
        
        # User-Agents pour rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
        ]
    
    def _sanitize_filename(self, url: str) -> str:
        """
        Nettoie l'URL pour créer un nom de fichier valide.
        
        Args:
            url: URL à nettoyer
        
        Returns:
            str: Nom de fichier sécurisé
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.replace('.', '_')
        port = f"_{parsed.port}" if parsed.port else ""
        path = parsed.path.replace('/', '_').replace('\\', '_')[:50]
        return f"{domain}{port}{path}.png"
    
    async def capture_single_url(self, url: str, user_agent: Optional[str] = None) -> ScreenshotResult:
        """
        Capture un screenshot d'une URL.
        
        Args:
            url: URL à capturer
            user_agent: User-Agent personnalisé (optionnel)
        
        Returns:
            ScreenshotResult: Résultat de la capture
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with async_playwright() as p:
                # Configuration du navigateur
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-accelerated-2d-canvas',
                        '--no-first-run',
                        '--no-zygote',
                        '--disable-gpu'
                    ]
                )
                
                context = await browser.new_context(
                    viewport={'width': self.viewport_width, 'height': self.viewport_height},
                    user_agent=user_agent or self.user_agents[0],
                    ignore_https_errors=True
                )
                
                page = await context.new_page()
                
                # Configuration des timeouts
                page.set_default_timeout(self.timeout)
                
                # Navigation vers l'URL
                response = await page.goto(url, wait_until='networkidle')
                
                # Attendre que la page soit complètement chargée
                await page.wait_for_load_state('networkidle')
                
                # Récupérer le titre de la page
                page_title = await page.title()
                
                # Générer le nom de fichier
                filename = self._sanitize_filename(url)
                screenshot_path = self.screenshot_dir / filename
                
                # Capture du screenshot
                await page.screenshot(
                    path=str(screenshot_path),
                    full_page=True,
                    type='png'
                )
                
                load_time = asyncio.get_event_loop().time() - start_time
                
                await browser.close()
                
                return ScreenshotResult(
                    url=url,
                    success=True,
                    screenshot_path=str(screenshot_path),
                    page_title=page_title,
                    viewport_size=(self.viewport_width, self.viewport_height),
                    load_time=load_time
                )
                
        except Exception as e:
            load_time = asyncio.get_event_loop().time() - start_time
            return ScreenshotResult(
                url=url,
                success=False,
                error_message=str(e),
                load_time=load_time
            )
    
    async def capture_multiple_urls(self, urls: List[str]) -> List[ScreenshotResult]:
        """
        Capture des screenshots de plusieurs URLs en parallèle.
        
        Args:
            urls: Liste des URLs à capturer
        
        Returns:
            List[ScreenshotResult]: Résultats des captures
        """
        semaphore = asyncio.Semaphore(3)  # Limiter à 3 captures simultanées
        
        async def capture_with_semaphore(url, index):
            async with semaphore:
                user_agent = self.user_agents[index % len(self.user_agents)]
                return await self.capture_single_url(url, user_agent)
        
        tasks = [capture_with_semaphore(url, i) for i, url in enumerate(urls)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtrer les exceptions
        valid_results = []
        for result in results:
            if isinstance(result, ScreenshotResult):
                valid_results.append(result)
            else:
                # Créer un résultat d'erreur pour les exceptions
                valid_results.append(ScreenshotResult(
                    url="unknown",
                    success=False,
                    error_message=str(result)
                ))
        
        return valid_results
    
    def get_screenshot_stats(self, results: List[ScreenshotResult]) -> Dict:
        """
        Génère des statistiques sur les captures.
        
        Args:
            results: Liste des résultats de capture
        
        Returns:
            Dict: Statistiques des captures
        """
        total = len(results)
        successful = len([r for r in results if r.success])
        failed = total - successful
        
        if successful > 0:
            avg_load_time = sum(r.load_time for r in results if r.success) / successful
        else:
            avg_load_time = 0
        
        return {
            "total_urls": total,
            "successful_captures": successful,
            "failed_captures": failed,
            "success_rate": (successful / total * 100) if total > 0 else 0,
            "average_load_time": avg_load_time,
            "screenshot_directory": str(self.screenshot_dir)
        }

# Fonction utilitaire
async def quick_screenshot(url: str, output_dir: str = "screenshots") -> ScreenshotResult:
    """
    Capture rapide d'un screenshot.
    
    Args:
        url: URL à capturer
        output_dir: Répertoire de sortie
    
    Returns:
        ScreenshotResult: Résultat de la capture
    """
    capturer = ScreenshotCapture(output_dir)
    return await capturer.capture_single_url(url) 