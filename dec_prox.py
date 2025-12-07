#DECODE BY ERROR TEAM
#DEC BY SAJU
import os
import sys
import time
import socket
import subprocess
import concurrent.futures
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

REQUIRED_PACKAGES = ['rich', 'requests', 'pysocks']

def ensure_packages():
    """Check imports and install missing packages via pip."""
    to_install = []
    for pkg in REQUIRED_PACKAGES:
        try:
            if pkg == 'pysocks':
                import socks
            else:
                __import__(pkg)
        except ImportError:
            to_install.append(pkg)
    
    if not to_install:
        return
    
    print(f"[INFO] Installing missing packages: {', '.join(to_install)}")
    cmd = [sys.executable, '-m', 'pip', 'install'] + to_install
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print('[INFO] Installation successful.')
            print('[INFO] Continuing with script...')
        else:
            print(f'[ERROR] Installation failed: {result.stderr}')
            print('Please install packages manually:')
            print(f"pip install {' '.join(to_install)}")
            sys.exit(1)
    except Exception as e:
        print(f'[ERROR] Installation error: {e}')
        print('Please install packages manually:')
        print(f"pip install {' '.join(to_install)}")
        sys.exit(1)

ensure_packages()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.live import Live
from rich import box
import requests

console = Console()

BANNER = '''
               [38;5;46mPPPPPP  RRRRRR   OOOOO  XX    XX YY   YY 
               [38;5;47mPP   PP RR   RR OO   OO  XX  XX  YY   YY 
               [38;5;48mPPPPPP  RRRRRR  OO   OO   XXXX    YYYYY  
               [38;5;49mPP      RR  RR  OO   OO  XX  XX    YYY   
               [38;5;49mPP      RR   RR  OOOO0  XX    XX   YYY   
'''

DEV_INFO = 'Developer: Abdur Rahim   |   GitHub: SHIHAB-X   |   Telegram: FLASH CYBER HUB'

DEFAULT_THREADS = 100
TCP_TIMEOUT = 3.0
REQ_TIMEOUT = 8.0
TEST_URL_HTTP = 'http://httpbin.org/ip'
TEST_URL_HTTPS = 'https://httpbin.org/ip'
GEO_API = 'http://ip-api.com/json/'

class ProxyResult:
    def __init__(self, proxy: str, protocol: str, alive: bool, latency: Optional[float] = None, country: str = 'Unknown', city: str = 'Unknown', anonymity: str = 'Unknown'):
        self.proxy = proxy
        self.protocol = protocol
        self.alive = alive
        self.latency = latency
        self.country = country
        self.city = city
        self.anonymity = anonymity
        self.timestamp = datetime.now().isoformat()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    sys.stdout.write(BANNER + '\n')
    console.print(Panel(DEV_INFO, style='bold cyan', padding=(0, 1)))

def prompt_menu() -> str:
    console.print('\n[bold green]Main Menu[/bold green]')
    console.print('[bold yellow]1[/bold yellow]. CHECK PROXY (Single Type)')
    console.print('[bold yellow]2[/bold yellow]. CHECK ALL PROXY TYPES (HTTP/HTTPS/SOCKS4/SOCKS5)')
    console.print('[bold yellow]3[/bold yellow]. CHECK PROXY WITH GEOLOCATION')
    console.print('[bold yellow]4[/bold yellow]. CHECK ANONYMITY LEVEL')
    console.print('[bold yellow]5[/bold yellow]. BATCH CHECK & EXPORT (JSON/CSV)')
    console.print('[bold yellow]6[/bold yellow]. CHECK IP')
    console.print('[bold yellow]7[/bold yellow]. Exit')
    return console.input('[bold cyan]Choose option:[/bold cyan] ').strip()

def prompt_proxy_type() -> str:
    console.print('\n[bold green]Select Proxy Type[/bold green]')
    console.print('[bold yellow]1[/bold yellow]. HTTP')
    console.print('[bold yellow]2[/bold yellow]. HTTPS')
    console.print('[bold yellow]3[/bold yellow]. SOCKS4')
    console.print('[bold yellow]4[/bold yellow]. SOCKS5')
    choice = console.input('[bold cyan]Choose:[/bold cyan] ').strip()
    return {'1': 'http', '2': 'https', '3': 'socks4', '4': 'socks5'}.get(choice, 'http')

def prompt_export_format() -> str:
    console.print('\n[bold green]Select Export Format[/bold green]')
    console.print('[bold yellow]1[/bold yellow]. TXT (IP:PORT)')
    console.print('[bold yellow]2[/bold yellow]. JSON (Detailed)')
    console.print('[bold yellow]3[/bold yellow]. CSV (Spreadsheet)')
    console.print('[bold yellow]4[/bold yellow]. ALL FORMATS')
    choice = console.input('[bold cyan]Choose:[/bold cyan] ').strip()
    return {'1': 'txt', '2': 'json', '3': 'csv', '4': 'all'}.get(choice, 'txt')

def read_proxy_file(path: str):
    p = Path(path)
    if not p.exists():
        console.print(f'[red]File not found: {path}[/red]')
        return []
    
    try:
        content = p.read_text(encoding='utf-8')
        proxies = [line.strip() for line in content.split('\n') if line.strip() and ':' in line]
        return proxies
    except Exception as e:
        console.print(f'[red]Error reading file: {e}[/red]')
        return []

def save_alive_list(alive_list, input_path: str):
    p = Path(input_path)
    out = p.parent / f'alive_{p.name}'
    try:
        out.write_text('\n'.join(alive_list), encoding='utf-8')
        return str(out)
    except Exception as e:
        console.print(f'[red]Error saving file: {e}[/red]')
        return None

def tcp_check(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def build_requests_proxies(proxy_type: str, raw: str) -> dict:
    if '://' in raw:
        proxy_target = raw
    else:
        proxy_target = f'{proxy_type}://{raw}'
    
    if proxy_target.startswith('socks5://'):
        proxy_target = proxy_target.replace('socks5://', 'socks5h://', 1)
    return {'http': proxy_target, 'https': proxy_target}

def get_proxy_geolocation(ip: str) -> Dict:
    """Get geolocation data for proxy IP"""
    try:
        r = requests.get(f'{GEO_API}{ip}', timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown')
            }
    except Exception:
        pass
    return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

def check_anonymity_level(proxy: str, protocol: str) -> str:
    """Check proxy anonymity level"""
    proxies = build_requests_proxies(protocol, proxy)
    try:
        r = requests.get('http://httpbin.org/headers', proxies=proxies, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            headers = r.json().get('headers', {})
            proxy_headers = ['X-Forwarded-For', 'Via', 'X-Real-Ip', 'Forwarded']
            found_headers = [h for h in proxy_headers if h in headers]
            
            if not found_headers:
                return 'Elite'
            if 'Via' in headers or 'X-Forwarded-For' in headers:
                return 'Anonymous'
            return 'Transparent'
        return 'Failed'
    except Exception:
        return 'Failed'

def test_proxy(protocol: str, raw_proxy: str, test_url: str, timeout: float = REQ_TIMEOUT):
    proxies = build_requests_proxies(protocol, raw_proxy)
    try:
        r = requests.get(test_url, proxies=proxies, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if 'origin' in data:
                return (True, r.elapsed)
        return (False, f'Invalid response: {r.status_code}')
    except requests.exceptions.RequestException as e:
        return (False, str(e))
    except ValueError:
        return (False, 'Invalid JSON response')

def test_proxy_advanced(protocol: str, raw_proxy: str, test_url: str, check_geo: bool = False, check_anon: bool = False):
    """Enhanced proxy testing with geolocation and anonymity"""
    proxies = build_requests_proxies(protocol, raw_proxy)
    try:
        r = requests.get(test_url, proxies=proxies, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            result = {
                'alive': True,
                'latency': round(r.elapsed.total_seconds() * 1000, 2),
                'ip': data.get('origin', 'Unknown').split(',')[0].strip()
            }
            if check_geo:
                geo = get_proxy_geolocation(result['ip'])
                result.update(geo)
            if check_anon:
                result['anonymity'] = check_anonymity_level(raw_proxy, protocol)
            return (True, result)
        return (False, f'Invalid response: {r.status_code}')
    except requests.exceptions.RequestException as e:
        return (False, str(e))
    except ValueError:
        return (False, 'Invalid JSON response')

def worker_check(raw_proxy: str, protocol: str, test_url: str):
    try:
        if '@' in raw_proxy:
            auth_part, host_port = raw_proxy.split('@', 1)
            host, port_str = host_port.split(':', 1)
        else:
            host, port_str = raw_proxy.split(':', 1)
        port = int(port_str)
    except (ValueError, IndexError):
        return (raw_proxy, False, 'invalid_format')
    
    if not tcp_check(host, port):
        return (raw_proxy, False, 'tcp_fail')
    
    ok, info = test_proxy(protocol, raw_proxy, test_url)
    if ok:
        latency = None
        if hasattr(info, 'total_seconds'):
            try:
                latency = round(info.total_seconds() * 1000, 2)
            except Exception:
                latency = 'ok'
        return (raw_proxy, True, latency)
    else:
        return (raw_proxy, False, str(info))

def worker_check_all_types(raw_proxy: str) -> Dict:
    """Check proxy against ALL proxy types (HTTP, HTTPS, SOCKS4, SOCKS5)"""
    try:
        if '@' in raw_proxy:
            auth_part, host_port = raw_proxy.split('@', 1)
            host, port_str = host_port.split(':', 1)
        else:
            host, port_str = raw_proxy.split(':', 1)
        port = int(port_str)
    except (ValueError, IndexError):
        return {'proxy': raw_proxy, 'results': {}}
    
    if not tcp_check(host, port):
        return {'proxy': raw_proxy, 'results': {}}
    
    results = {}
    protocols = {
        'HTTP': ('http', TEST_URL_HTTP),
        'HTTPS': ('https', TEST_URL_HTTPS),
        'SOCKS4': ('socks4', TEST_URL_HTTP),
        'SOCKS5': ('socks5', TEST_URL_HTTP)
    }
    
    for name, (protocol, test_url) in protocols.items():
        ok, info = test_proxy(protocol, raw_proxy, test_url, timeout=5.0)
        if ok:
            latency = round(info.total_seconds() * 1000, 2) if hasattr(info, 'total_seconds') else 'ok'
            results[name] = {'alive': True, 'latency': latency}
        else:
            results[name] = {'alive': False, 'error': str(info)[:50]}
    
    return {'proxy': raw_proxy, 'results': results}

def worker_check_advanced(raw_proxy: str, protocol: str, test_url: str, check_geo: bool = False, check_anon: bool = False):
    """Advanced worker with geo and anonymity checking"""
    try:
        if '@' in raw_proxy:
            auth_part, host_port = raw_proxy.split('@', 1)
            host, port_str = host_port.split(':', 1)
        else:
            host, port_str = raw_proxy.split(':', 1)
        port = int(port_str)
    except (ValueError, IndexError):
        return ProxyResult(raw_proxy, protocol, False)
    
    if not tcp_check(host, port):
        return ProxyResult(raw_proxy, protocol, False)
    
    ok, info = test_proxy_advanced(protocol, raw_proxy, test_url, check_geo, check_anon)
    if ok:
        return ProxyResult(
            raw_proxy, protocol, True,
            info.get('latency'),
            info.get('country', 'Unknown'),
            info.get('city', 'Unknown'),
            info.get('anonymity', 'Unknown')
        )
    return ProxyResult(raw_proxy, protocol, False)

def export_txt(results: List[ProxyResult], output_path: str):
    """Export to TXT format"""
    alive = [r.proxy for r in results if r.alive]
    Path(output_path).write_text('\n'.join(alive), encoding='utf-8')

def export_json(results: List[ProxyResult], output_path: str):
    """Export to JSON format"""
    data = []
    for r in results:
        if r.alive:
            data.append({
                'proxy': r.proxy,
                'protocol': r.protocol,
                'latency_ms': r.latency,
                'country': r.country,
                'city': r.city,
                'anonymity': r.anonymity,
                'timestamp': r.timestamp
            })
    Path(output_path).write_text(json.dumps(data, indent=2), encoding='utf-8')

def export_csv(results: List[ProxyResult], output_path: str):
    """Export to CSV format"""
    lines = ['Proxy,Protocol,Latency(ms),Country,City,Anonymity,Timestamp']
    for r in results:
        if r.alive:
            lines.append(f'{r.proxy},{r.protocol},{r.latency},{r.country},{r.city},{r.anonymity},{r.timestamp}')
    Path(output_path).write_text('\n'.join(lines), encoding='utf-8')

def check_proxies_interactive():
    """Original proxy checker"""
    path = console.input('\n[bold cyan]Enter path to proxy file (IP:PORT per line):[/bold cyan] ').strip()
    if not path:
        console.print('[red]No path provided.[/red]')
        return
    
    proxies = read_proxy_file(path)
    if not proxies:
        console.print('[red]No proxies found in the file.[/red]')
        return
    
    protocol = prompt_proxy_type()
    test_url = TEST_URL_HTTP if protocol in ['http', 'socks4', 'socks5'] else TEST_URL_HTTPS
    
    threads_input = console.input(f'[bold cyan]Threads (default {DEFAULT_THREADS}): [/bold cyan]').strip()
    try:
        max_workers = int(threads_input) if threads_input else DEFAULT_THREADS
        max_workers = max(1, min(max_workers, 500))
    except ValueError:
        max_workers = DEFAULT_THREADS
    
    total = len(proxies)
    alive = []
    dead = []
    progress = Progress(
        SpinnerColumn(),
        TextColumn('{task.description}'),
        BarColumn(),
        '[progress.percentage]{task.percentage:>3.0f}%',
        TimeElapsedColumn(),
        TimeRemainingColumn()
    )
    task = progress.add_task('Checking proxies...', total=total)
    start_time = time.time()
    
    with Live(console=console, refresh_per_second=10), progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(worker_check, proxy, protocol, test_url): proxy for proxy in proxies}
            for future in concurrent.futures.as_completed(futures):
                proxy_line = futures[future]
                try:
                    raw, ok, info = future.result()
                except Exception as e:
                    raw, ok, info = (proxy_line, False, str(e))
                
                if ok:
                    alive.append(f'{raw} | {info}ms' if isinstance(info, (int, float)) else raw)
                    progress.update(task, advance=1, description=f'[green]ALIVE[/green] {len(alive)}/{total}')
                else:
                    dead.append(f'{raw} | {info}')
                    progress.update(task, advance=1, description=f'[red]DEAD[/red]  {len(dead)}/{total}')
    
    elapsed = time.time() - start_time
    console.print('\n')
    tbl = Table(title='Scan Summary', box=box.SIMPLE)
    tbl.add_column('Total', justify='right')
    tbl.add_column('Alive', justify='right', style='green')
    tbl.add_column('Dead', justify='right', style='red')
    tbl.add_column('Time(s)', justify='right')
    tbl.add_column('Speed', justify='right')
    tbl.add_row(str(total), str(len(alive)), str(len(dead)), f'{elapsed:.2f}', f'{total / elapsed:.2f} proxies/s')
    console.print(tbl)
    
    if alive:
        clean_alive = [proxy.split(' | ')[0] for proxy in alive]
        out_path = save_alive_list(clean_alive, path)
        if out_path:
            console.print(f'[bold green]Saved alive proxies -> {out_path}[/bold green]')
    
    if dead:
        dead_path = Path(path).parent / f'dead_{Path(path).name}'
        try:
            dead_path.write_text('\n'.join(dead), encoding='utf-8')
            console.print(f'[bold yellow]Saved dead proxies -> {dead_path}[/bold yellow]')
        except Exception as e:
            console.print(f'[red]Error saving dead proxies: {e}[/red]')

def check_all_proxy_types():
    """Check proxies against ALL types: HTTP, HTTPS, SOCKS4, SOCKS5"""
    path = console.input('\n[bold cyan]Enter path to proxy file:[/bold cyan] ').strip()
    if not path:
        console.print('[red]No path provided.[/red]')
        return
    
    proxies = read_proxy_file(path)
    if not proxies:
        console.print('[red]No proxies found.[/red]')
        return
    
    threads_input = console.input(f'[bold cyan]Threads (default {DEFAULT_THREADS}):[/bold cyan] ').strip()
    try:
        max_workers = int(threads_input) if threads_input else DEFAULT_THREADS
        max_workers = max(1, min(max_workers, 300))
    except ValueError:
        max_workers = DEFAULT_THREADS
    
    total = len(proxies)
    all_results = []
    progress = Progress(
        SpinnerColumn(),
        TextColumn('[bold blue]{task.description}'),
        BarColumn(),
        '[progress.percentage]{task.percentage:>3.0f}%',
        TimeElapsedColumn(),
        TimeRemainingColumn()
    )
    task = progress.add_task('Testing all proxy types...', total=total)
    start_time = time.time()
    
    with Live(console=console, refresh_per_second=10):
        with progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(worker_check_all_types, proxy): proxy for proxy in proxies}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        all_results.append(result)
                        progress.update(task, advance=1)
                    except Exception:
                        progress.update(task, advance=1)
    
    elapsed = time.time() - start_time
    console.print('\n')
    summary_tbl = Table(title='All Types Scan Summary', box=box.DOUBLE)
    summary_tbl.add_column('Type', style='bold cyan')
    summary_tbl.add_column('Alive', justify='right', style='green')
    summary_tbl.add_column('Dead', justify='right', style='red')
    
    type_stats = {
        'HTTP': {'alive': 0, 'dead': 0},
        'HTTPS': {'alive': 0, 'dead': 0},
        'SOCKS4': {'alive': 0, 'dead': 0},
        'SOCKS5': {'alive': 0, 'dead': 0}
    }
    
    for result in all_results:
        for ptype in ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5']:
            if ptype in result['results']:
                if result['results'][ptype]['alive']:
                    type_stats[ptype]['alive'] += 1
                else:
                    type_stats[ptype]['dead'] += 1
    
    for ptype in ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5']:
        summary_tbl.add_row(ptype, str(type_stats[ptype]['alive']), str(type_stats[ptype]['dead']))
    
    console.print(summary_tbl)
    console.print(f'\n[bold]Total Proxies Tested:[/bold] {total}')
    console.print(f'[bold]Time Taken:[/bold] {elapsed:.2f}s')
    console.print(f'[bold]Speed:[/bold] {total / elapsed:.2f} proxies/s')
    
    detail_tbl = Table(title='Working Proxies (Top 20)', box=box.ROUNDED)
    detail_tbl.add_column('Proxy', style='yellow')
    detail_tbl.add_column('HTTP', justify='center')
    detail_tbl.add_column('HTTPS', justify='center')
    detail_tbl.add_column('SOCKS4', justify='center')
    detail_tbl.add_column('SOCKS5', justify='center')
    
    working_proxies = [r for r in all_results if any(r['results'].get(t, {}).get('alive', False) for t in ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5'])][:20]
    for result in working_proxies:
        row = [result['proxy']]
        for ptype in ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5']:
            if ptype in result['results'] and result['results'][ptype]['alive']:
                latency = result['results'][ptype]['latency']
                row.append(f'[green]✓ {latency}ms[/green]')
            else:
                row.append('[red]✗[/red]')
        detail_tbl.add_row(*row)
    
    if working_proxies:
        console.print('\n')
        console.print(detail_tbl)
    
    base_path = Path(path).parent / Path(path).stem
    for ptype in ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5']:
        alive_proxies = [r['proxy'] for r in all_results if r['results'].get(ptype, {}).get('alive', False)]
        if alive_proxies:
            output_file = f'{base_path}_alive_{ptype.lower()}.txt'
            Path(output_file).write_text('\n'.join(alive_proxies), encoding='utf-8')
            console.print(f'[green]Saved {ptype} proxies -> {output_file}[/green]')
    
    json_output = f'{base_path}_all_types_detailed.json'
    Path(json_output).write_text(json.dumps(all_results, indent=2), encoding='utf-8')
    console.print(f'[green]Saved detailed results -> {json_output}[/green]')

def check_proxies_with_geo():
    """Check proxies with geolocation"""
    path = console.input('\n[bold cyan]Enter path to proxy file:[/bold cyan] ').strip()
    if not path:
        console.print('[red]No path provided.[/red]')
        return
    
    proxies = read_proxy_file(path)
    if not proxies:
        console.print('[red]No proxies found.[/red]')
        return
    
    protocol = prompt_proxy_type()
    test_url = TEST_URL_HTTP if protocol in ['http', 'socks4', 'socks5'] else TEST_URL_HTTPS
    
    threads_input = console.input(f'[bold cyan]Threads (default {DEFAULT_THREADS}):[/bold cyan] ').strip()
    try:
        max_workers = int(threads_input) if threads_input else DEFAULT_THREADS
        max_workers = max(1, min(max_workers, 500))
    except ValueError:
        max_workers = DEFAULT_THREADS
    
    total = len(proxies)
    results = []
    progress = Progress(
        SpinnerColumn(),
        TextColumn('[bold blue]{task.description}'),
        BarColumn(),
        '[progress.percentage]{task.percentage:>3.0f}%',
        TimeElapsedColumn(),
        TimeRemainingColumn()
    )
    task = progress.add_task('Checking with geolocation...', total=total)
    start_time = time.time()
    alive_count = 0
    
    with Live(console=console, refresh_per_second=10):
        with progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(worker_check_advanced, proxy, protocol, test_url, True, False): proxy for proxy in proxies}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                        if result.alive:
                            alive_count += 1
                            progress.update(task, advance=1, description=f'[green]ALIVE[/green] {alive_count}/{total}')
                        else:
                            progress.update(task, advance=1, description=f'[red]DEAD[/red] {len(results) - alive_count}/{total}')
                    except Exception:
                        progress.update(task, advance=1)
    
    elapsed = time.time() - start_time
    console.print('\n')
    tbl = Table(title='Geo Scan Summary', box=box.DOUBLE_EDGE)
    tbl.add_column('Total', justify='center')
    tbl.add_column('Alive', justify='center', style='green')
    tbl.add_column('Dead', justify='center', style='red')
    tbl.add_column('Time', justify='center')
    tbl.add_column('Speed', justify='center')
    tbl.add_row(str(total), str(alive_count), str(len(results) - alive_count), f'{elapsed:.2f}s', f'{total / elapsed:.2f} p/s')
    console.print(tbl)
    
    alive_results = [r for r in results if r.alive][:15]
    if alive_results:
        detail_tbl = Table(title='Geolocation Details (Top 15)', box=box.ROUNDED)
        detail_tbl.add_column('Proxy', style='cyan')
        detail_tbl.add_column('Latency', justify='right')
        detail_tbl.add_column('Country', style='yellow')
        detail_tbl.add_column('City', style='yellow')
        for r in alive_results:
            detail_tbl.add_row(r.proxy, f'{r.latency}ms', r.country, r.city)
        console.print('\n')
        console.print(detail_tbl)
    
    if alive_count > 0:
        export_format = prompt_export_format()
        base_path = Path(path).parent / f'alive_geo_{Path(path).stem}'
        if export_format in ['txt', 'all']:
            export_txt(results, f'{base_path}.txt')
            console.print(f'[green]Saved TXT: {base_path}.txt[/green]')
        if export_format in ['json', 'all']:
            export_json(results, f'{base_path}.json')
            console.print(f'[green]Saved JSON: {base_path}.json[/green]')
        if export_format in ['csv', 'all']:
            export_csv(results, f'{base_path}.csv')
            console.print(f'[green]Saved CSV: {base_path}.csv[/green]')

def check_anonymity_interactive():
    """Check anonymity level for a single proxy"""
    proxy = console.input('\n[bold cyan]Enter proxy (IP:PORT):[/bold cyan] ').strip()
    if not proxy:
        console.print('[red]No proxy provided.[/red]')
        return
    
    protocol = prompt_proxy_type()
    with console.status('[bold green]Checking anonymity level...', spinner='dots'):
        anon = check_anonymity_level(proxy, protocol)
    
    result_tbl = Table(title='Anonymity Check Result', box=box.DOUBLE)
    result_tbl.add_column('Proxy', style='cyan')
    result_tbl.add_column('Protocol', style='yellow')
    result_tbl.add_column('Anonymity Level', style='magenta')
    
    if anon == 'Elite':
        level_display = '[bold green]Elite (Best)[/bold green]'
    elif anon == 'Anonymous':
        level_display = '[bold yellow]Anonymous (Good)[/bold yellow]'
    elif anon == 'Transparent':
        level_display = '[bold red]Transparent (Low)[/bold red]'
    else:
        level_display = '[bold red]Failed[/bold red]'
    
    result_tbl.add_row(proxy, protocol.upper(), level_display)
    console.print('\n')
    console.print(result_tbl)

def batch_check_export():
    """Batch check with advanced export options"""
    path = console.input('\n[bold cyan]Enter path to proxy file:[/bold cyan] ').strip()
    if not path:
        console.print('[red]No path provided.[/red]')
        return
    
    proxies = read_proxy_file(path)
    if not proxies:
        console.print('[red]No proxies found.[/red]')
        return
    
    protocol = prompt_proxy_type()
    test_url = TEST_URL_HTTP if protocol in ['http', 'socks4', 'socks5'] else TEST_URL_HTTPS
    
    check_geo = console.input('[bold cyan]Include geolocation? (y/n):[/bold cyan] ').strip().lower() == 'y'
    check_anon = console.input('[bold cyan]Include anonymity check? (y/n):[/bold cyan] ').strip().lower() == 'y'
    
    threads_input = console.input(f'[bold cyan]Threads (default {DEFAULT_THREADS}):[/bold cyan] ').strip()
    try:
        max_workers = int(threads_input) if threads_input else DEFAULT_THREADS
        max_workers = max(1, min(max_workers, 500))
    except ValueError:
        max_workers = DEFAULT_THREADS
    
    total = len(proxies)
    results = []
    progress = Progress(
        SpinnerColumn(),
        TextColumn('[bold blue]{task.description}'),
        BarColumn(),
        '[progress.percentage]{task.percentage:>3.0f}%',
        TimeElapsedColumn(),
        TimeRemainingColumn()
    )
    task = progress.add_task('Batch checking...', total=total)
    start_time = time.time()
    alive_count = 0
    
    with Live(console=console, refresh_per_second=10):
        with progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(worker_check_advanced, proxy, protocol, test_url, check_geo, check_anon): proxy for proxy in proxies}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                        if result.alive:
                            alive_count += 1
                            progress.update(task, advance=1, description=f'[green]ALIVE[/green] {alive_count}/{total}')
                        else:
                            progress.update(task, advance=1, description=f'[red]DEAD[/red] {len(results) - alive_count}/{total}')
                    except Exception:
                        progress.update(task, advance=1)
    
    elapsed = time.time() - start_time
    console.print('\n')
    tbl = Table(title='Batch Scan Summary', box=box.DOUBLE_EDGE)
    tbl.add_column('Total', justify='center')
    tbl.add_column('Alive', justify='center', style='green')
    tbl.add_column('Dead', justify='center', style='red')
    tbl.add_column('Time', justify='center')
    tbl.add_row(str(total), str(alive_count), str(len(results) - alive_count), f'{elapsed:.2f}s')
    console.print(tbl)
    
    if alive_count > 0:
        export_format = prompt_export_format()
        base_path = Path(path).parent / f'batch_{Path(path).stem}'
        if export_format in ['txt', 'all']:
            export_txt(results, f'{base_path}.txt')
            console.print(f'[green]Saved TXT: {base_path}.txt[/green]')
        if export_format in ['json', 'all']:
            export_json(results, f'{base_path}.json')
            console.print(f'[green]Saved JSON: {base_path}.json[/green]')
        if export_format in ['csv', 'all']:
            export_csv(results, f'{base_path}.csv')
            console.print(f'[green]Saved CSV: {base_path}.csv[/green]')

def check_ip():
    """Check public IP with geolocation"""
    console.print('\n[bold green]Detecting public IP...[/bold green]')
    try:
        with console.status('[bold green]Fetching data...', spinner='dots'):
            r = requests.get('https://api.ipify.org?format=json', timeout=10)
            if r.status_code == 200:
                ip = r.json()['ip']
                geo = get_proxy_geolocation(ip)
                info_tbl = Table(title='Your IP Information', box=box.DOUBLE)
                info_tbl.add_column('Property', style='bold cyan')
                info_tbl.add_column('Value', style='bold yellow')
                info_tbl.add_row('IP Address', ip)
                info_tbl.add_row('Country', geo['country'])
                info_tbl.add_row('City', geo['city'])
                info_tbl.add_row('ISP', geo['isp'])
                console.print('\n')
                console.print(info_tbl)
            else:
                console.print(f'[red]Failed to fetch IP. Status code: {r.status_code}[/red]')
    except Exception as e:
        console.print(f'[red]Failed to fetch IP: {e}[/red]')

def main():
    clear_screen()
    print_banner()
    while True:
        try:
            choice = prompt_menu()
            if choice == '1':
                check_proxies_interactive()
            elif choice == '2':
                check_all_proxy_types()
            elif choice == '3':
                check_proxies_with_geo()
            elif choice == '4':
                check_anonymity_interactive()
            elif choice == '5':
                batch_check_export()
            elif choice == '6':
                check_ip()
            elif choice == '7':
                console.print('[bold red]Goodbye![/bold red]')
                return
            else:
                console.print('[red]Invalid choice. Try again.[/red]')
            
            if choice != '7':
                console.input('\nPress Enter to continue...')
                clear_screen()
                print_banner()
        except KeyboardInterrupt:
            console.print('\n[red]Interrupted. Exiting...[/red]')
            return
        except Exception as e:
            console.print(f'\n[red]Unexpected error: {e}[/red]')
            console.input('Press Enter to continue...')
            clear_screen()
            print_banner()

if __name__ == '__main__':

    main()
