import asyncio
import pandas as pd
import subprocess
from collections import defaultdict

FILE_PATH = "datos_columnas_filtradas.txt"

# Almacena ASNs ya consultados para evitar consultas repetidas
asn_cache = {}

# Limitar el número de consultas simultáneas (por ejemplo, 10 consultas concurrentes)
SEMAPHORE_LIMIT = 10
semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)

async def is_asn_registered(asn):
    """Verifica si un ASN está registrado usando WHOIS de forma asíncrona."""
    if asn in asn_cache:
        return asn_cache[asn]

    # Usamos el semáforo para limitar el número de consultas concurrentes
    async with semaphore:
        try:
            process = await asyncio.create_subprocess_exec(
                "whois", f"AS{asn}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            # Depuración: muestra la salida cruda del comando whois
            print(f"Consulta WHOIS para ASN {asn}: {stdout.decode()[:500]}...")  # Imprime los primeros 500 caracteres para depuración

            rir_keywords = ['ARIN', 'RIPE', 'APNIC', 'LACNIC', 'AFRINIC']

            # Verifica si la salida contiene alguno de los RIRs
            registered = any(keyword in stdout.decode() for keyword in rir_keywords)

            # Si no se encuentra un RIR, podemos analizar más a fondo para ver qué devuelve el whois
            if not registered:
                print(f"ASN {asn} no encontrado en los RIRs. Salida WHOIS completa:")
                print(stdout.decode())  # Mostramos la salida completa para la depuración

            # Cacheamos el resultado para evitar consultas repetidas
            asn_cache[asn] = registered
            return registered

        except Exception as e:
            print(f"Error al consultar ASN {asn}: {e}")
            asn_cache[asn] = False
            return False

async def process_file():
    """Carga el archivo, procesa los ASNs y cuenta prefijos anunciados por ASNs no registrados."""
    # Carga rápida del archivo con pandas
    df = pd.read_csv(FILE_PATH, delimiter='|', header=None, names=["prefix", "as_path"])
    
    # Extraer ASNs como listas
    df["asns"] = df["as_path"].apply(lambda x: x.strip().split())

    # Expandir la tabla para asignar cada prefijo a todos los ASNs en su AS_PATH
    df_expanded = df.explode("asns")[["asns", "prefix"]]

    # Agrupar prefijos por ASN
    asn_to_prefixes = df_expanded.groupby("asns")["prefix"].apply(list)

    # Lista de ASNs únicos para consulta Whois
    unique_asns = list(asn_to_prefixes.index)

    # Consultar Whois en paralelo con el semáforo limitando las consultas
    tasks = [is_asn_registered(asn) for asn in unique_asns]
    results = await asyncio.gather(*tasks)

    # Filtrar ASNs no registrados y contar sus prefijos
    unregistered_asns = {}
    for asn, registered in zip(unique_asns, results):
        if not registered:
            unregistered_asns[asn] = asn_to_prefixes[asn]

    # Mostrar resultados
    print("\n🔍 **ASNs NO REGISTRADOS Y SUS PREFIJOS** 🔍")
    for asn, prefixes in unregistered_asns.items():
        print(f"ASN {asn} -> {len(prefixes)} prefijos asociados ❌")

    print(f"\n🔴 Total de ASNs no registrados: {len(unregistered_asns)}")
    print(f"🔴 Total de prefijos afectados por ASNs no registrados: {sum(len(prefixes) for prefixes in unregistered_asns.values())}")

# Ejecutar la función asíncrona
asyncio.run(process_file())
