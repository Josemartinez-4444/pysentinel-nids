import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, wrpcap
from database import registrar_alerta

CAPTURAS_DIR = Path(__file__).resolve().parent.parent / "capturas"
CAPTURAS_DIR.mkdir(exist_ok=True)


class NetworkMonitor:
    def __init__(self, on_alerta_callback=None, on_paquete_callback=None):
        self.on_alerta = on_alerta_callback
        self.on_paquete = on_paquete_callback
        self.ejecutando = False

        # Buffer circular con los últimos 100 paquetes para guardar evidencia .pcap
        self.buffer_paquetes = deque(maxlen=100)

        # Control de escaneo de puertos: {ip_origen: [(timestamp, puerto_destino), ...]}
        self.actividad_puertos = defaultdict(list)
        # Tabla ARP conocida para detectar ARP Spoofing: {ip: mac}
        self.tabla_arp = {}
        # Evitar spam de alertas repetidas de la misma IP en menos de 15 segundos
        self.ultima_alerta = {}

        # Contadores de protocolos para estadísticas en vivo
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTROS": 0, "TOTAL": 0}

    def _puede_alertar(self, clave: str, cooldown: int = 15) -> bool:
        ahora = time.time()
        if ahora - self.ultima_alerta.get(clave, 0) > cooldown:
            self.ultima_alerta[clave] = ahora
            return True
        return False

    def _guardar_evidencia_pcap(self, prefijo: str) -> str:
        """Guarda los paquetes recientes en un .pcap listo para abrir en Wireshark."""
        marca = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"{prefijo}_{marca}.pcap"
        ruta = CAPTURAS_DIR / nombre_archivo
        wrpcap(str(ruta), list(self.buffer_paquetes))
        return nombre_archivo

    def _disparar_alerta(self, tipo: str, severidad: str, ip_origen: str, detalle: str):
        pcap = self._guardar_evidencia_pcap(tipo.lower().replace(" ", "_"))
        alerta = registrar_alerta(tipo, severidad, ip_origen, detalle, pcap)
        print(f"[ALERTA {severidad}] {tipo} desde {ip_origen}: {detalle} (Evidencia: {pcap})")
        if self.on_alerta:
            self.on_alerta(alerta)

    def procesar_paquete(self, pkt):
        self.buffer_paquetes.append(pkt)
        self.stats["TOTAL"] += 1
        ahora = time.time()

        resumen_pkt = None

        # 1. Detección de ARP Spoofing (ataques Man-in-the-Middle en red local)
        if pkt.haslayer(ARP):
            self.stats["ARP"] += 1
            if pkt[ARP].op == 2:  # ARP Reply ("is-at")
                ip_src = pkt[ARP].psrc
                mac_src = pkt[ARP].hwsrc
                if ip_src in self.tabla_arp and self.tabla_arp[ip_src] != mac_src:
                    if self._puede_alertar(f"arp_{ip_src}"):
                        self._disparar_alerta(
                            "ARP Spoofing / MITM",
                            "CRÍTICA",
                            ip_src,
                            f"La IP {ip_src} cambió de MAC ({self.tabla_arp[ip_src]} -> {mac_src})",
                        )
                self.tabla_arp[ip_src] = mac_src
            resumen_pkt = {"proto": "ARP", "origen": pkt[ARP].psrc, "destino": pkt[ARP].pdst, "info": f"op={pkt[ARP].op}"}

        # 2. Análisis de paquetes IP (TCP, UDP, ICMP)
        elif pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

            if pkt.haslayer(TCP):
                self.stats["TCP"] += 1
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                flags = str(pkt[TCP].flags)
                resumen_pkt = {"proto": "TCP", "origen": f"{ip_src}:{sport}", "destino": f"{ip_dst}:{dport}", "info": f"Flags [{flags}]"}

                # Detección de Port Scan (paquetes SYN hacia múltiples puertos distintos)
                if "S" in flags and "A" not in flags:
                    self.actividad_puertos[ip_src].append((ahora, dport))
                    # Mantener solo actividad de los últimos 5 segundos
                    self.actividad_puertos[ip_src] = [
                        (t, p) for t, p in self.actividad_puertos[ip_src] if ahora - t <= 5
                    ]
                    puertos_unicos = {p for _, p in self.actividad_puertos[ip_src]}

                    if len(puertos_unicos) >= 12 and self._puede_alertar(f"scan_{ip_src}"):
                        self._disparar_alerta(
                            "Port Scan (SYN)",
                            "ALTA",
                            ip_src,
                            f"Escaneo detectado: {len(puertos_unicos)} puertos distintos sondeados en <5s",
                        )

            elif pkt.haslayer(UDP):
                self.stats["UDP"] += 1
                resumen_pkt = {"proto": "UDP", "origen": f"{ip_src}:{pkt[UDP].sport}", "destino": f"{ip_dst}:{pkt[UDP].dport}", "info": f"Len {len(pkt)}"}

            elif pkt.haslayer(ICMP):
                self.stats["ICMP"] += 1
                resumen_pkt = {"proto": "ICMP", "origen": ip_src, "destino": ip_dst, "info": f"Type {pkt[ICMP].type}"}

            else:
                self.stats["OTROS"] += 1

        if resumen_pkt and self.on_paquete:
            self.on_paquete(resumen_pkt)

    def iniciar(self):
        if self.ejecutando:
            return
        self.ejecutando = True
        hilo = threading.Thread(
            target=lambda: sniff(prn=self.procesar_paquete, store=False, stop_filter=lambda _: not self.ejecutando),
            daemon=True,
        )
        hilo.start()

    def detener(self):
        self.ejecutando = False