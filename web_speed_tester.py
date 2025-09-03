#!/usr/bin/env python3
"""
Programa para medir velocidad de descarga de sitios web completos
Incluye descarga de todos los assets (CSS, JS, imágenes) con medición detallada
+ NUEVAS CARACTERÍSTICAS: Detección de CDN y geolocalización por país
+ MONGODB INTEGRATION: Envío automático de resultados a servidor MongoDB externo
"""

import requests
import time
import re
import urllib.parse
import json
import socket
from datetime import datetime, timezone
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
import hashlib
import platform

# Importar MongoDB
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, OperationFailure
    MONGODB_AVAILABLE = True
except ImportError:
    print("⚠️  PyMongo no está instalado. Para instalar: pip3 install pymongo")
    MONGODB_AVAILABLE = False

# Patch hashlib para SCRAM authentication en Termux
def patch_hashlib():
    """Parche para habilitar SCRAM authentication en Termux"""
    if not hasattr(hashlib, 'pbkdf2_hmac'):
        print("🔧 Aplicando parche para autenticación SCRAM...")
        
        try:
            from passlib.utils.pbkdf2 import pbkdf2
            
            def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
                """Implementación alternativa de pbkdf2_hmac usando passlib"""
                return pbkdf2(password, salt, iterations, keylen=dklen, prf=f"hmac-{hash_name}")
            
            # Aplicar el parche
            hashlib.pbkdf2_hmac = pbkdf2_hmac
            print("✅ Parche SCRAM aplicado exitosamente")
            return True
            
        except ImportError:
            print("⚠️  Passlib no disponible - SCRAM no funcionará")
        except Exception as e:
            print(f"⚠️  Error aplicando parche: {e}")
    
    return hasattr(hashlib, 'pbkdf2_hmac')


class MongoDBManager:
    """Gestor de conexión y envío de datos a MongoDB"""
    
    def __init__(self, host="glmuller.ddns.net", port=27017, database="web_speed_tests", collection="test_results", username="admin", password="password123"):
        self.host = host
        self.port = port
        self.database_name = database
        self.collection_name = collection
        self.username = username
        self.password = password
        self.client = None
        self.db = None
        self.collection = None
        self.connected = False

        # Aplicar parche SCRAM si MongoDB está disponible
        if MONGODB_AVAILABLE:
            self.scram_available = patch_hashlib()
        else:
            self.scram_available = False
        
        if MONGODB_AVAILABLE:
            self._connect()
    
    def _connect(self):
        """Establece conexión con MongoDB con autenticación user/password SCRAM"""
        try:
            print(f"🔌 Conectando a MongoDB: {self.host}:{self.port}")
            
            # Configurar parámetros de conexión
            connection_params = {
                'host': self.host,
                'port': self.port,
                'serverSelectionTimeoutMS': 10000,
                'connectTimeoutMS': 10000,
                'socketTimeoutMS': 10000
            }
            
            # Configurar autenticación user/password con SCRAM
            if self.username and self.password:
                print(f"🔐 Autenticando usuario: {self.username}")
                
                if hasattr(self, 'scram_available') and self.scram_available:
                    print("✅ Usando autenticación SCRAM-SHA-1")
                    connection_params.update({
                        'username': self.username,
                        'password': self.password,
                        'authSource': 'admin',
                        'authMechanism': 'SCRAM-SHA-1'
                    })
                else:
                    print("⚠️  SCRAM no disponible, intentando sin autenticación")
            
            # Establecer conexión
            self.client = MongoClient(**connection_params)
            self.client.admin.command('ping')
            
            # Configurar base de datos y colección
            self.db = self.client[self.database_name]
            self.collection = self.db[self.collection_name]
            
            # Verificar permisos de escritura
            try:
                test_doc = {"_test": True, "timestamp": datetime.now(timezone.utc)}
                result = self.collection.insert_one(test_doc)
                self.collection.delete_one({"_id": result.inserted_id})
                
                print("✅ Conexión exitosa con permisos de escritura")
                print(f"📊 Base de datos: {self.database_name}")
                print(f"📁 Colección: {self.collection_name}")
                self.connected = True
                
            except OperationFailure as e:
                if "authentication" in str(e).lower() or "unauthorized" in str(e).lower():
                    print("❌ Error de autenticación o permisos")
                    print("💡 Verificar credenciales de usuario/contraseña")
                    self.connected = False
                else:
                    raise e
                    
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"❌ Error de conexión: {e}")
            self.connected = False
        except OperationFailure as e:
            print(f"❌ Error de operación: {e}")
            if "authentication" in str(e).lower():
                print("🔐 Error de autenticación user/password")
                print("💡 Verificar que el usuario y contraseña sean correctos")
            self.connected = False
        except Exception as e:
            print(f"❌ Error inesperado: {e}")
            self.connected = False

    def send_results(self, test_results):
        """Envía los resultados de pruebas a MongoDB"""
        if not self.connected or not MONGODB_AVAILABLE:
            return False
        
        try:
            # Preparar documento para MongoDB
            document = self._prepare_document(test_results)
            
            print(f"📤 Enviando resultados a MongoDB...")
            
            # Insertar documento
            result = self.collection.insert_one(document)
            
            print(f"✅ Resultados enviados exitosamente a MongoDB")
            print(f"🆔 ID del documento: {result.inserted_id}")
            
            return True
            
        except OperationFailure as e:
            if "authentication" in str(e).lower() or "unauthorized" in str(e).lower():
                print(f"❌ Error de autenticación al insertar: {e}")
                print("🔐 El servidor requiere credenciales válidas para escritura")
            else:
                print(f"❌ Error de operación MongoDB: {e}")
            return False
        except Exception as e:
            print(f"❌ Error enviando datos a MongoDB: {e}")
            return False
    
    def _prepare_document(self, test_results):
        """Prepara el documento para MongoDB con metadatos adicionales"""
        
        # Generar ID único para esta sesión de pruebas
        session_id = str(uuid.uuid4())
        
        # Obtener información del dispositivo
        device_info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor(),
        }
        
        # Crear documento con metadatos
        document = {
            '_id': session_id,
            'test_session': {
                'session_id': session_id,
                'timestamp': datetime.now(timezone.utc),  # Fixed deprecation warning
                'local_timestamp': datetime.now().isoformat(),
                'device_info': device_info,
                'total_sites_tested': len(test_results),
                'test_duration_seconds': self._calculate_total_duration(test_results)
            },
            'test_results': test_results,
            'summary_stats': self._generate_summary_stats(test_results)
        }
        
        return document
    
    def _calculate_total_duration(self, test_results):
        """Calcula la duración total de todas las pruebas"""
        total_time = 0
        for result in test_results:
            if result.get('summary', {}).get('total_time'):
                total_time += result['summary']['total_time']
        return round(total_time, 2)
    
    def _generate_summary_stats(self, test_results):
        """Genera estadísticas de resumen de todas las pruebas"""
        
        all_countries = {}
        all_cdns = {}
        total_assets = 0
        total_size = 0
        
        for result in test_results:
            summary = result.get('summary', {})
            
            # Contadores generales
            total_assets += summary.get('successful_assets', 0)
            total_size += summary.get('total_size', 0)
            
            # Agregar países
            by_country = summary.get('by_country', {})
            for country, stats in by_country.items():
                if country not in all_countries:
                    all_countries[country] = {'count': 0, 'total_time': 0, 'total_size': 0}
                all_countries[country]['count'] += stats['count']
                all_countries[country]['total_time'] += stats['total_time']
                all_countries[country]['total_size'] += stats['total_size']
            
            # Agregar CDNs
            by_cdn = summary.get('by_cdn', {})
            for cdn, stats in by_cdn.items():
                if cdn not in all_cdns:
                    all_cdns[cdn] = {'count': 0, 'total_time': 0, 'total_size': 0}
                all_cdns[cdn]['count'] += stats['count']
                all_cdns[cdn]['total_time'] += stats['total_time']
                all_cdns[cdn]['total_size'] += stats['total_size']
        
        return {
            'total_assets': total_assets,
            'total_size_mb': round(total_size / 1024 / 1024, 2),
            'countries': all_countries,
            'cdns': all_cdns,
            'top_country': max(all_countries.items(), key=lambda x: x[1]['count'])[0] if all_countries else None,
            'top_cdn': max(all_cdns.items(), key=lambda x: x[1]['count'])[0] if all_cdns else None
        }
    
    def close(self):
        """Cierra la conexión con MongoDB"""
        if self.client and self.connected:
            self.client.close()
            print("🔌 Conexión MongoDB cerrada")

class CDNGeoDetector:
    """Detector de CDN y geolocalización integrado"""
    
    def __init__(self):
        # Patrones conocidos de CDNs
        self.cdn_patterns = {
            'CloudFlare': [r'\.cloudflare\.', r'\.cf-', r'cdnjs\.cloudflare\.com'],
            'AWS CloudFront': [r'\.cloudfront\.net', r'd[0-9a-z]+\.cloudfront\.net'],
            'Google CDN': [r'\.googleapis\.com', r'\.gstatic\.com', r'\.googleusercontent\.com', r'\.google\.com'],
            'Akamai': [r'\.akamai\.', r'\.akamaized\.net', r'\.akamaitechnologies\.'],
            'Fastly': [r'\.fastly\.com', r'\.fastlylb\.net'],
            'KeyCDN': [r'\.keycdn\.com'],
            'BunnyCDN': [r'\.b-cdn\.net'],
            'Amazon S3': [r's3\.amazonaws\.com', r's3-[a-z0-9-]+\.amazonaws\.com'],
            'Microsoft Azure': [r'\.azureedge\.net', r'\.azure\.com'],
            'Facebook CDN': [r'\.fbcdn\.net', r'\.facebook\.com'],
            'YouTube CDN': [r'\.ytimg\.com', r'\.youtube\.com', r'\.googlevideo\.com'],
            'Twitter CDN': [r'\.twimg\.com'],
            'GitHub CDN': [r'\.githubusercontent\.com', r'\.githubassets\.com'],
            'JSDelivr': [r'\.jsdelivr\.net'],
            'MaxCDN': [r'\.maxcdn\.com', r'\.stackpathcdn\.com'],
        }
        
        # Cache para evitar múltiples consultas
        self.ip_cache = {}
        self.geo_cache = {}
    
    def detect_cdn(self, url):
        """Detecta el CDN basado en la URL"""
        domain = urllib.parse.urlparse(url).netloc.lower()
        
        for cdn_name, patterns in self.cdn_patterns.items():
            for pattern in patterns:
                if re.search(pattern, domain):
                    return cdn_name
        
        return "Direct/Unknown"
    
    def get_ip_address(self, hostname):
        """Obtiene la dirección IP de un hostname"""
        if hostname in self.ip_cache:
            return self.ip_cache[hostname]
        
        try:
            ip = socket.gethostbyname(hostname)
            self.ip_cache[hostname] = ip
            return ip
        except socket.gaierror:
            return None
    
    def get_country_from_ip(self, ip):
        """Obtiene el país desde la IP usando APIs gratuitas"""
        if not ip or ip in self.geo_cache:
            return self.geo_cache.get(ip, 'Unknown')
        
        # Probar diferentes APIs en orden
        apis = [
            lambda ip: self._try_ip_api_com(ip),
            lambda ip: self._try_ipapi_co(ip),
            lambda ip: self._try_ipinfo_io(ip),
        ]
        
        for api_func in apis:
            try:
                country = api_func(ip)
                if country and country != 'Unknown':
                    self.geo_cache[ip] = country
                    return country
            except:
                continue
        
        # Fallback
        self.geo_cache[ip] = 'Unknown'
        return 'Unknown'
    
    def _try_ip_api_com(self, ip):
        """Prueba con ip-api.com (muy confiable)"""
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=country', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') != 'fail':
                return data.get('country', 'Unknown')
        return None
    
    def _try_ipapi_co(self, ip):
        """Prueba con ipapi.co"""
        response = requests.get(f'http://ipapi.co/{ip}/country_name/', timeout=5)
        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
        return None
    
    def _try_ipinfo_io(self, ip):
        """Prueba con ipinfo.io"""
        response = requests.get(f'http://ipinfo.io/{ip}/country', timeout=5)
        if response.status_code == 200 and len(response.text.strip()) == 2:
            # Convertir código de país a nombre (básico)
            country_codes = {
                'US': 'United States', 'BR': 'Brazil', 'AR': 'Argentina',
                'DE': 'Germany', 'FR': 'France', 'GB': 'United Kingdom',
                'CA': 'Canada', 'JP': 'Japan', 'CN': 'China',
                'IN': 'India', 'AU': 'Australia', 'MX': 'Mexico'
            }
            code = response.text.strip().upper()
            return country_codes.get(code, f'Country-{code}')
        return None

class WebSpeedTester:
    def __init__(self):
        self.session = requests.Session()
        self.cdn_detector = CDNGeoDetector()
        
        # Headers para evitar cache y simular navegador real
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.session.headers.update(self.headers)
    def get_public_ip(self):
        """Obtiene la dirección IP pública del dispositivo (UE)"""
        result = {'ipv4': None, 'ipv6': None}
        
        # Intentar obtener IPv4 usando api.ipify.org (más confiable)
        try:
            ipv4_response = requests.get('https://api.ipify.org', timeout=8, headers={'User-Agent': 'curl/7.0'})
            if ipv4_response.status_code == 200:
                ip = ipv4_response.text.strip()
                if ip and '.' in ip and ':' not in ip:  # Validar que es IPv4
                    result['ipv4'] = ip
        except:
            # Fallback a ifconfig.me para IPv4
            try:
                ipv4_response = requests.get('https://ipv4.ifconfig.me', timeout=8, headers={'User-Agent': 'curl/7.0'})
                if ipv4_response.status_code == 200:
                    ip = ipv4_response.text.strip()
                    if ip and '.' in ip and ':' not in ip:
                        result['ipv4'] = ip
            except:
                pass
        
        # Intentar obtener IPv6 usando api64.ipify.org o ifconfig.me
        try:
            ipv6_response = requests.get('https://api64.ipify.org', timeout=8, headers={'User-Agent': 'curl/7.0'})
            if ipv6_response.status_code == 200:
                ip = ipv6_response.text.strip()
                if ip and ':' in ip:  # Validar que es IPv6
                    result['ipv6'] = ip
        except:
            # Fallback a ifconfig.me para IPv6
            try:
                ipv6_response = requests.get('https://ipv6.ifconfig.me', timeout=8, headers={'User-Agent': 'curl/7.0'})
                if ipv6_response.status_code == 200:
                    ip = ipv6_response.text.strip()
                    if ip and ':' in ip:
                        result['ipv6'] = ip
            except:
                pass
        
        # Si aún no tenemos nada, usar ifconfig.me general como último recurso
        if not result['ipv4'] and not result['ipv6']:
            try:
                response = requests.get('https://ifconfig.me', timeout=8, headers={'User-Agent': 'curl/7.0'})
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip:
                        if ':' in ip:
                            result['ipv6'] = ip
                        elif '.' in ip:
                            result['ipv4'] = ip
            except:
                pass
        
        return result
    def extract_assets_from_html(self, html_content, base_url):
        """Extrae todas las URLs de assets del HTML"""
        assets = {
            'css': [],
            'js': [],
            'images': [],
            'fonts': [],
            'other': []
        }
        
        # Patrones para extraer diferentes tipos de assets
        patterns = {
            'css': [
                r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\'][^>]*>',
                r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
            ],
            'js': [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\'][^>]*>',
                r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
            ],
            'images': [
                r'<img[^>]+src=["\']([^"\']+)["\'][^>]*>',
                r'<source[^>]+src=["\']([^"\']+)["\'][^>]*>',
                r'<source[^>]+srcset=["\']([^"\']+)["\'][^>]*>',
            ],
            'fonts': [
                r'@font-face[^}]*url\(["\']?([^"\')\s]+)["\']?\)',
                r'<link[^>]+href=["\']([^"\']+\.(?:woff2?|ttf|eot|otf))["\'][^>]*>',
            ]
        }
        
        for asset_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    # Saltear URLs problemáticas
                    if match.startswith(('data:', 'javascript:', 'mailto:')):
                        continue
                    
                    # Convertir URL relativa a absoluta
                    if match.startswith('//'):
                        match = 'https:' + match
                    elif match.startswith('/'):
                        match = urllib.parse.urljoin(base_url, match)
                    elif not match.startswith(('http://', 'https://')):
                        match = urllib.parse.urljoin(base_url, match)
                    
                    if match not in assets[asset_type]:
                        assets[asset_type].append(match)
        
        return assets
    
    def download_asset(self, url, asset_type):
        """Descarga un asset individual y mide el tiempo + detecta CDN y país"""
        start_time = time.time()
        hostname = urllib.parse.urlparse(url).netloc
        
        # Detectar CDN
        cdn = self.cdn_detector.detect_cdn(url)
        
        # Obtener IP y país
        ip = self.cdn_detector.get_ip_address(hostname)
        country = self.cdn_detector.get_country_from_ip(ip) if ip else 'Unknown'
        
        try:
            response = self.session.get(url, timeout=30, stream=True)
            
            # Medir tiempo de primera respuesta
            first_byte_time = time.time() - start_time
            
            # Descargar contenido completo
            content_length = 0
            for chunk in response.iter_content(chunk_size=8192):
                content_length += len(chunk)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            return {
                'url': url,
                'type': asset_type,
                'hostname': hostname,
                'ip_address': ip,
                'country': country,
                'cdn': cdn,
                'status_code': response.status_code,
                'size_bytes': content_length,
                'total_time': total_time,
                'first_byte_time': first_byte_time,
                'success': True,
                'error': None
            }
            
        except Exception as e:
            end_time = time.time()
            return {
                'url': url,
                'type': asset_type,
                'hostname': hostname,
                'ip_address': ip,
                'country': country,
                'cdn': cdn,
                'status_code': 0,
                'size_bytes': 0,
                'total_time': end_time - start_time,
                'first_byte_time': 0,
                'success': False,
                'error': str(e)
            }
    
    def test_website_speed(self, url, max_workers=10):
        """Prueba la velocidad completa de un sitio web con info geo-CDN"""
        print(f"\n{'='*70}")
        print(f"🌍 Probando sitio: {url}")
        print(f"{'='*70}")
        
        # Obtener IP pública al inicio del test
        print("🌐 Obteniendo IP pública del dispositivo...")
        public_ip = self.get_public_ip()
        
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'public_ip': public_ip,
            'main_page': None,
            'assets': [],
            'summary': {}
        }
        
        # Descargar página principal
        print("📥 Descargando página principal...")
        main_start = time.time()
        
        try:
            response = self.session.get(url, timeout=30)
            main_end = time.time()
            main_time = main_end - main_start
            
            # Obtener info geo-CDN de la página principal
            main_hostname = urllib.parse.urlparse(url).netloc
            main_ip = self.cdn_detector.get_ip_address(main_hostname)
            main_country = self.cdn_detector.get_country_from_ip(main_ip) if main_ip else 'Unknown'
            main_cdn = self.cdn_detector.detect_cdn(url)
            
            results['main_page'] = {
                'status_code': response.status_code,
                'size_bytes': len(response.content),
                'total_time': main_time,
                'hostname': main_hostname,
                'ip_address': main_ip,
                'country': main_country,
                'cdn': main_cdn,
                'success': True
            }
            
            print(f"✅ Página principal: {response.status_code} - {len(response.content):,} bytes - {main_time:.2f}s")
            print(f"🌐 Servidor: {main_ip} | 🌎 País: {main_country} | 🔗 CDN: {main_cdn}")
            
            # Extraer assets
            print("\n🔍 Extrayendo assets...")
            assets = self.extract_assets_from_html(response.text, url)
            
            # Mostrar resumen de assets encontrados
            total_assets = sum(len(asset_list) for asset_list in assets.values())
            print(f"📦 Assets encontrados: {total_assets}")
            for asset_type, asset_list in assets.items():
                if asset_list:
                    print(f"   {asset_type}: {len(asset_list)}")
            
            # Descargar assets en paralelo
            print(f"\n📥 Descargando assets con análisis geo-CDN...")
            all_assets = []
            for asset_type, asset_list in assets.items():
                for asset_url in asset_list:
                    all_assets.append((asset_url, asset_type))
            
            if all_assets:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_asset = {
                        executor.submit(self.download_asset, asset_url, asset_type): (asset_url, asset_type)
                        for asset_url, asset_type in all_assets
                    }
                    
                    completed = 0
                    for future in as_completed(future_to_asset):
                        result = future.result()
                        results['assets'].append(result)
                        completed += 1
                        
                        status = "✅" if result['success'] else "❌"
                        country = result['country'][:15]
                        cdn_name = result['cdn'][:15]
                        
                        print(f"{status} [{completed:2d}/{len(all_assets)}] {result['type'][:6]:6s} {result['total_time']:.2f}s {result['size_bytes']:8,} bytes | 🌎 {country:15s} | 🔗 {cdn_name:15s}")
                        
                        if not result['success']:
                            print(f"    ❌ Error: {result['error']}")
            
        except Exception as e:
            main_end = time.time()
            results['main_page'] = {
                'status_code': 0,
                'size_bytes': 0,
                'total_time': main_end - main_start,
                'success': False,
                'error': str(e)
            }
            print(f"❌ Error descargando página principal: {e}")
            return results
        
        # Calcular resumen con info geo-CDN
        self.calculate_summary(results)
        
        return results
    
    def calculate_summary(self, results):
        """Calcula estadísticas de resumen incluyendo geo-CDN"""
        assets = results['assets']
        main_page = results['main_page']
        
        # Estadísticas básicas
        total_assets = len(assets)
        successful_assets = len([a for a in assets if a['success']])
        failed_assets = total_assets - successful_assets
        
        # Tiempos
        main_time = main_page['total_time'] if main_page['success'] else 0
        asset_times = [a['total_time'] for a in assets if a['success']]
        total_asset_time = sum(asset_times)
        total_time = main_time + total_asset_time
        
        # Tamaños
        main_size = main_page['size_bytes'] if main_page['success'] else 0
        asset_sizes = [a['size_bytes'] for a in assets if a['success']]
        total_asset_size = sum(asset_sizes)
        total_size = main_size + total_asset_size
        
        # Por tipo de asset
        by_type = {}
        for asset in assets:
            asset_type = asset['type']
            if asset_type not in by_type:
                by_type[asset_type] = {
                    'count': 0,
                    'successful': 0,
                    'total_time': 0,
                    'total_size': 0,
                    'avg_time': 0
                }
            
            by_type[asset_type]['count'] += 1
            if asset['success']:
                by_type[asset_type]['successful'] += 1
                by_type[asset_type]['total_time'] += asset['total_time']
                by_type[asset_type]['total_size'] += asset['size_bytes']
        
        # Calcular promedios
        for asset_type in by_type:
            if by_type[asset_type]['successful'] > 0:
                by_type[asset_type]['avg_time'] = by_type[asset_type]['total_time'] / by_type[asset_type]['successful']
        
        # NUEVO: Estadísticas por país y CDN
        by_country = {}
        by_cdn = {}
        
        # Incluir página principal
        if main_page['success']:
            main_country = main_page.get('country', 'Unknown')
            main_cdn = main_page.get('cdn', 'Unknown')
            
            by_country[main_country] = by_country.get(main_country, {'count': 0, 'total_time': 0, 'total_size': 0})
            by_country[main_country]['count'] += 1
            by_country[main_country]['total_time'] += main_page['total_time']
            by_country[main_country]['total_size'] += main_page['size_bytes']
            
            by_cdn[main_cdn] = by_cdn.get(main_cdn, {'count': 0, 'total_time': 0, 'total_size': 0})
            by_cdn[main_cdn]['count'] += 1
            by_cdn[main_cdn]['total_time'] += main_page['total_time']
            by_cdn[main_cdn]['total_size'] += main_page['size_bytes']
        
        # Incluir assets
        for asset in assets:
            if asset['success']:
                country = asset.get('country', 'Unknown')
                cdn = asset.get('cdn', 'Unknown')
                
                by_country[country] = by_country.get(country, {'count': 0, 'total_time': 0, 'total_size': 0})
                by_country[country]['count'] += 1
                by_country[country]['total_time'] += asset['total_time']
                by_country[country]['total_size'] += asset['size_bytes']
                
                by_cdn[cdn] = by_cdn.get(cdn, {'count': 0, 'total_time': 0, 'total_size': 0})
                by_cdn[cdn]['count'] += 1
                by_cdn[cdn]['total_time'] += asset['total_time']
                by_cdn[cdn]['total_size'] += asset['size_bytes']
        
        results['summary'] = {
            'total_assets': total_assets,
            'successful_assets': successful_assets,
            'failed_assets': failed_assets,
            'main_page_time': main_time,
            'total_asset_time': total_asset_time,
            'total_time': total_time,
            'main_page_size': main_size,
            'total_asset_size': total_asset_size,
            'total_size': total_size,
            'avg_asset_time': sum(asset_times) / len(asset_times) if asset_times else 0,
            'max_asset_time': max(asset_times) if asset_times else 0,
            'min_asset_time': min(asset_times) if asset_times else 0,
            'by_type': by_type,
            'by_country': by_country,  # NUEVO
            'by_cdn': by_cdn          # NUEVO
        }
    
    def print_detailed_report(self, results):
        """Imprime reporte detallado de los resultados incluyendo geo-CDN"""
        print(f"\n{'='*70}")
        print(f"📊 REPORTE DETALLADO - {results['url']}")
        print(f"{'='*70}")
        
        summary = results['summary']
        
        # Mostrar IP pública del UE
        public_ip = results.get('public_ip', {})
        if public_ip.get('ipv4') or public_ip.get('ipv6'):
            print(f"\n🌐 IP PÚBLICA DEL DISPOSITIVO (UE):")
            if public_ip.get('ipv4'):
                print(f"   IPv4: {public_ip['ipv4']}")
            if public_ip.get('ipv6'):
                print(f"   IPv6: {public_ip['ipv6']}")
        
        print(f"\n📈 RESUMEN GENERAL:")
        print(f"   Página principal: {summary['main_page_time']:.2f}s ({summary['main_page_size']:,} bytes)")
        print(f"   Assets totales: {summary['total_assets']} (exitosos: {summary['successful_assets']}, fallidos: {summary['failed_assets']})")
        print(f"   Tiempo total: {summary['total_time']:.2f}s")
        print(f"   Tamaño total: {summary['total_size']:,} bytes ({summary['total_size']/1024/1024:.2f} MB)")
        
        print(f"\n⏱️  ESTADÍSTICAS DE TIEMPO:")
        print(f"   Tiempo promedio por asset: {summary['avg_asset_time']:.3f}s")
        print(f"   Asset más lento: {summary['max_asset_time']:.3f}s")
        print(f"   Asset más rápido: {summary['min_asset_time']:.3f}s")
        
        # NUEVO: Estadísticas por país
        print(f"\n🌎 DISTRIBUCIÓN POR PAÍS:")
        by_country = summary.get('by_country', {})
        for country, stats in sorted(by_country.items(), key=lambda x: x[1]['count'], reverse=True):
            avg_time = stats['total_time'] / stats['count'] if stats['count'] > 0 else 0
            print(f"   {country:20s}: {stats['count']:2d} recursos, {avg_time:.3f}s promedio, {stats['total_size']/1024:.1f} KB")
        
        # NUEVO: Estadísticas por CDN
        print(f"\n🔗 DISTRIBUCIÓN POR CDN:")
        by_cdn = summary.get('by_cdn', {})
        for cdn, stats in sorted(by_cdn.items(), key=lambda x: x[1]['count'], reverse=True):
            avg_time = stats['total_time'] / stats['count'] if stats['count'] > 0 else 0
            print(f"   {cdn:20s}: {stats['count']:2d} recursos, {avg_time:.3f}s promedio, {stats['total_size']/1024:.1f} KB")
        
        print(f"\n📁 POR TIPO DE ASSET:")
        for asset_type, stats in summary['by_type'].items():
            if stats['count'] > 0:
                success_rate = (stats['successful'] / stats['count']) * 100
                print(f"   {asset_type.upper()}:")
                print(f"     Cantidad: {stats['count']} (éxito: {success_rate:.1f}%)")
                print(f"     Tiempo total: {stats['total_time']:.2f}s")
                print(f"     Tiempo promedio: {stats['avg_time']:.3f}s")
                print(f"     Tamaño total: {stats['total_size']:,} bytes")
        
        print(f"\n🐌 ASSETS MÁS LENTOS (Top 10):")
        slow_assets = sorted(
            [a for a in results['assets'] if a['success']], 
            key=lambda x: x['total_time'], 
            reverse=True
        )[:10]
        
        for i, asset in enumerate(slow_assets, 1):
            url_short = asset['url'][:50] + "..." if len(asset['url']) > 50 else asset['url']
            country = asset['country'][:15]
            cdn = asset['cdn'][:15]
            print(f"   {i:2d}. {asset['total_time']:.3f}s | {country:15s} | {cdn:15s} | {asset['type']} - {url_short}")
        
        if results['assets'] and any(not a['success'] for a in results['assets']):
            print(f"\n❌ ASSETS FALLIDOS:")
            failed_assets = [a for a in results['assets'] if not a['success']]
            for asset in failed_assets:
                url_short = asset['url'][:60] + "..." if len(asset['url']) > 60 else asset['url']
                print(f"   {asset['type']} - {url_short}")
                print(f"     Error: {asset['error']}")

def main():
    """Función principal"""
    # Sitios web a probar
    websites = [
        "https://www.google.com",
        "https://www.youtube.com", 
        "https://www.facebook.com"
    ]
    
    # Inicializar componentes
    tester = WebSpeedTester()
    
    # CONFIGURACIÓN MONGODB - Ajustar según tu servidor
    # Opción 1: Sin autenticación (servidor abierto)
    # FIXED: Using correct authentication configuration
    mongo_manager = MongoDBManager(
        host="glmuller.ddns.net", 
        port=27017, 
        username="admin",
        password="password123",
        database="web_speed_tests",
        collection="test_results"
    )
    # Opción 2: Con autenticación (descomenta y configura si es necesario)
    # mongo_manager = MongoDBManager(
    #     host="glmuller.ddns.net", 
    #     port=27017, 
    #     username="tu_usuario",
    #     password="tu_password"
    # )
    
    all_results = []
    
    print("🚀 INICIANDO PRUEBAS DE VELOCIDAD WEB CON GEO-CDN")
    print(f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🌍 Incluye detección de CDN y geolocalización por país")
    print("📤 Con envío automático a MongoDB")
    
    for website in websites:
        try:
            result = tester.test_website_speed(website)
            all_results.append(result)
            tester.print_detailed_report(result)
            
        except KeyboardInterrupt:
            print("\n⏹️  Prueba interrumpida por el usuario")
            break
        except Exception as e:
            print(f"❌ Error probando {website}: {e}")
    
    # Guardar resultados en archivo JSON local
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"web_speed_geo_results_{timestamp}.json"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Resultados guardados localmente en: {filename}")
    except Exception as e:
        print(f"❌ Error guardando resultados localmente: {e}")
    
    # NUEVO: Enviar resultados a MongoDB
    if all_results:
        print(f"\n{'='*70}")
        print("📤 ENVIANDO RESULTADOS A MONGODB")
        print(f"{'='*70}")
        
        success = mongo_manager.send_results(all_results)
        if success:
            print("✅ Datos enviados exitosamente a MongoDB")
        else:
            print("❌ No se pudieron enviar los datos a MongoDB")
            print("💡 Para configurar autenticación, edita las credenciales en main()")
    
    # Cerrar conexión MongoDB
    mongo_manager.close()
    
    # Resumen comparativo con info geo-CDN
    if len(all_results) > 1:
        print(f"\n{'='*70}")
        print("📊 COMPARACIÓN ENTRE SITIOS (con info Geo-CDN)")
        print(f"{'='*70}")
        
        for result in all_results:
            summary = result['summary']
            main_page = result.get('main_page', {})
            
            print(f"\n🌐 {result['url']}:")
            print(f"   Tiempo total: {summary['total_time']:.2f}s")
            print(f"   Tamaño total: {summary['total_size']/1024/1024:.2f} MB")
            print(f"   Assets: {summary['successful_assets']}/{summary['total_assets']}")
            print(f"   Servidor principal: {main_page.get('country', 'Unknown')} ({main_page.get('cdn', 'Unknown')})")
            
            # Top países
            countries = summary.get('by_country', {})
            top_countries = sorted(countries.items(), key=lambda x: x[1]['count'], reverse=True)[:3]
            if top_countries:
                countries_str = ", ".join([f"{country} ({stats['count']})" for country, stats in top_countries])
                print(f"   Principales países: {countries_str}")

if __name__ == "__main__":
    main()
