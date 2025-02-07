import asyncio
import pandas as pd
import ipaddress
from collections import defaultdict

# Variables
FILE_PATH = "datos_columnas_filtradas.txt"


SEMAPHORE_LIMIT = 200
semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
asn_cache = {}

# Nodo del trie de Patricia
class PatriciaTrieNode:
    def __init__(self):
        self.children = {}
        self.network = None
        self.is_aggregated = False

# Trie de Patricia
class PatriciaTrie:
    def __init__(self):
        self.root = PatriciaTrieNode()

    def insert(self, network):
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)[:network.prefixlen]
        for bit in prefix_str:
            if bit not in node.children:
                node.children[bit] = PatriciaTrieNode()
            node = node.children[bit]
        node.network = network

    def find_supernet_or_contiguous(self, network):
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)
        supernet_candidate = None

        for bit in prefix_str:
            if bit in node.children:
                node = node.children[bit]
                if node.network and node.network.prefixlen < network.prefixlen:
                    supernet_candidate = node.network
            else:
                break

        if node and node.network:
            next_prefix = network.network_address + (1 << (128 - network.prefixlen))
            if node.network.network_address == next_prefix:
                return node.network

        return supernet_candidate

    def mark_as_aggregated(self, network):
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)[:network.prefixlen]
        for bit in prefix_str:
            node = node.children[bit]
        if node.network == network:
            node.is_aggregated = True

# Función para verificar si un ASN está registrado
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

            # Intentamos decodificar la salida en UTF-8, pero en caso de error usamos una codificación más permisiva
            try:
                output = stdout.decode('utf-8')
            except UnicodeDecodeError:
                # Usamos 'latin-1' que es más permisiva para los bytes no válidos
                output = stdout.decode('latin-1')

            # Depuración: muestra la salida cruda del comando whois
#            print(f"Consulta WHOIS para ASN {asn}: {output[:500]}...")  # Imprime los primeros 500 caracteres para depuración

            rir_keywords = ['ARIN', 'RIPE', 'APNIC', 'LACNIC', 'AFRINIC']

            # Verifica si la salida contiene alguno de los RIRs
            registered = any(keyword in output for keyword in rir_keywords)

            # Si no se encuentra un RIR, podemos analizar más a fondo para ver qué devuelve el whois
            if not registered:
                 pass
         #       print(f"ASN {asn} no encontrado en los RIRs. Salida WHOIS completa:")
 #               print(output)  # Mostramos la salida completa para la depuración

            # Cacheamos el resultado para evitar consultas repetidas
            asn_cache[asn] = registered
            return registered

        except Exception as e:
            print(f"Error al consultar ASN {asn}: {e}")
            asn_cache[asn] = False
            return False

# Limpieza del AS Path
def clean_as_path(as_path):
    return as_path.replace("{", "").replace("}", "").replace(",", " ").split()

# Análisis de prefijos IPv6
async def analyze_ipv6_prefixes(file_path):
    df = pd.read_csv(file_path, delimiter='|', header=None, names=["prefix", "as_path"])
    df['network'] = df['prefix'].apply(lambda x: ipaddress.ip_network(x.strip(), strict=False))
    df['origin_as'] = df['as_path'].apply(lambda x: clean_as_path(x)[-1])

    trie = PatriciaTrie()
    for network in df['network'].drop_duplicates():
        trie.insert(network)

    total_prefijos = len(df['network'].drop_duplicates())
    total_prefix_length = sum(network.prefixlen for network in df['network'].drop_duplicates())
    average_prefix_length = total_prefix_length / total_prefijos if total_prefijos else 0

    print(f"Total de prefijos únicos: {total_prefijos}")
    print(f"Average Prefix Length: {average_prefix_length:.2f}")

    # Optimizar la búsqueda de ASNs no registrados
    grouped_as = df.groupby('origin_as')
    max_agg_prefixes_count = 0
    aggregated_networks = set()

    tasks = []
    for origin_as, group in grouped_as:
        networks = sorted(group['network'].drop_duplicates().tolist(), key=lambda x: (x.prefixlen, x.network_address))
        aggregated_in_as = set()

        for i in range(len(networks)):
            network = networks[i]
            if network in aggregated_in_as:
                continue

            supernet_or_contiguous = trie.find_supernet_or_contiguous(network)
            if supernet_or_contiguous:
                max_agg_prefixes_count += 1
                aggregated_in_as.add(network)
                trie.mark_as_aggregated(network)
                aggregated_in_as.add(supernet_or_contiguous)

        aggregated_networks.update(aggregated_in_as)

    print(f"Maximum Aggregateable Prefixes: {max_agg_prefixes_count}")
    print(f"Unaggregateables Prefixes: {total_prefijos - max_agg_prefixes_count}")



    #se divide el total de prefijos unicos anunciado y la cantidad de prefijos luego de aplicar el numero maximo prefijos agregables 
    print(f"Factor de desagregación: {total_prefijos / len(aggregated_networks) if aggregated_networks else 0:.2f}")

    df['as_path_length'] = df['as_path'].apply(lambda x: len(clean_as_path(x)))
    print(f"Longest AS-Path: {df['as_path_length'].max()}")
    print(f"Average AS-Path: {df['as_path_length'].mean():.2f}")

    # Consultar Whois en paralelo con los ASNs únicos
    unique_asns = list(df['origin_as'].drop_duplicates())
    tasks = [is_asn_registered(asn) for asn in unique_asns]
    results = await asyncio.gather(*tasks)

    unregistered_asns = {}
    for asn, registered in zip(unique_asns, results):
        if not registered:
            unregistered_asns[asn] = df[df['origin_as'] == asn]['prefix'].tolist()

   # print("\n ASNs NO REGISTRADOS Y SUS PREFIJOS*")
  #  for asn, prefixes in unregistered_asns.items():
   #     print(f"ASN {asn} -> {len(prefixes)} prefijos asociados ")

    print(f"Total de ASNs no registrados: {len(unregistered_asns)}")
    print(f"prefijos de ASNs no registrados: {sum(len(prefixes) for prefixes in unregistered_asns.values())}")

# Ejecutar el análisis asíncrono
asyncio.run(analyze_ipv6_prefixes(FILE_PATH))
