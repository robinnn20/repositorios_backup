import asyncio
import pandas as pd
import ipaddress
from collections import defaultdict
import re

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
        #Convierte la dirección de la red IPv6 (network.network_address) en un número entero, lo convierte a binario y luego lo transforma en una cadena binaria de 128 bits, rellenando con ceros a la izquierda si es necesario.
        #Esto facilita la comparación bit a bit de las direcciones de red.
        prefix_str = bin(int(network.network_address))[2:].zfill(128)
        supernet_candidate = None

        #Recorre cada bit del prefijo de la red (en formato binario).
        #Por cada bit, verifica si existe un nodo hijo correspondiente en el Trie:
            #Si existe, navega a ese nodo hijo y revisa si ese nodo tiene una red (node.network) cuyo prefijo es más corto que el de la red que se está evaluando (node.network.prefixlen < network.prefixlen).
                #Si cumple con la condición de ser una red más amplia (un posible supernet), se marca como el candidato a supernet (supernet_candidate = node.network).
            #Si no se encuentra un nodo hijo para el bit actual, el ciclo se interrumpe con break, lo que indica que no se puede seguir buscando en ese camino del Trie.
        for bit in prefix_str:
            if bit in node.children:
                node = node.children[bit]
                if node.network and node.network.prefixlen < network.prefixlen:
                    supernet_candidate = node.network
            else:
                break

      #  if node and node.network:
       #     next_prefix = network.network_address + (1 << (128 - network.prefixlen))
        #    if node.network.network_address == next_prefix:
         #       return node.network

        return supernet_candidate

    def mark_as_aggregated(self, network):
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)[:network.prefixlen]
        for bit in prefix_str:
            node = node.children[bit]
        if node.network == network:
            node.is_aggregated = True

# Función para verificar si un ASN está registrado
#La función es asíncrona, lo que permite ejecutar la consulta WHOIS sin bloquear el flujo del programa. El parámetro asn es el número del sistema autónomo que se desea verificar.
async def is_asn_registered(asn):
#Antes de realizar una nueva consulta, la función verifica si el resultado de la consulta del ASN ya está almacenado en un caché llamado asn_cache.
#Si ya se ha consultado previamente, retorna el valor del caché, evitando hacer una consulta innecesaria.
    if asn in asn_cache:
        return asn_cache[asn]

    async with semaphore:
        try:
            #Se crea un proceso asíncrono que ejecuta el comando whois para consultar la base de datos whois.radb.net sobre el ASN proporcionado.
            #stdout contiene la salida del proceso (la respuesta del servidor WHOIS), y stderr contiene cualquier error o mensaje de advertencia.
            process = await asyncio.create_subprocess_exec(
                "whois", "-h", "whois.radb.net", f"AS{asn}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            try:
                output = stdout.decode('utf-8')
            except UnicodeDecodeError:
                output = stdout.decode('latin-1')

            # Expresión regular para detectar respuestas de ASNs no registrados
            #Se utiliza una expresión regular para buscar términos en la respuesta que indiquen que el ASN no está registrado, como "denied", "not found" o "invalid".
            #Si se encuentra alguno de estos términos, se marca el ASN como no registrado en el caché (asn_cache) y se devuelve False.
            if re.search(r"(denied|not found|no entries found|error|invalid|does not exist)", output, re.IGNORECASE):
                asn_cache[asn] = False
                return False
            #Si no se encuentra ninguna de las respuestas de error, el ASN se considera registrado, se guarda en el caché como True y se retorna True
            asn_cache[asn] = True
            return True

        except Exception as e:
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
#Se agrupa el DataFrame por la columna origin_as, que contiene el AS de origen.
#Se inicializan las variables max_agg_prefixes_count para contar el número de prefijos agregados y aggregated_networks para almacenar las redes que se han agregado.
    grouped_as = df.groupby('origin_as')
    max_agg_prefixes_count = 0
    aggregated_networks = set()

    for origin_as, group in grouped_as:

        #Se itera sobre cada grupo de AS, ordenando los prefijos del grupo según su longitud (prefixlen) y la dirección de la red (network_address). 
        #Luego, se inicializa un conjunto aggregated_in_as para almacenar las redes agregadas dentro de ese AS.
        networks = sorted(group['network'].drop_duplicates().tolist(), key=lambda x: (x.prefixlen, x.network_address))
        aggregated_in_as = set()


        #Para cada red en el grupo de AS, se busca si existe un supernet o red contigua usando el método find_supernet_or_contiguous del trie.
        #Si se encuentra una red agregada (un supernet o red contigua),
        #se incrementa el contador max_agg_prefixes_count, se marca la red como agregada y se añade tanto la red como su supernet o red contigua al conjunto aggregated_in_as
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
    #se filtran las redes dentro del conjunto aggregated_in_as para asegurarse de que no haya ninguna red más específica (con mayor longitud de prefijo) que sea igual en dirección de red. 
    #Las redes que cumplen este criterio se añaden al conjunto aggregated_networks.
        for network in aggregated_in_as:
            if not any(other_network.prefixlen > network.prefixlen and other_network.network_address == network.network_address for other_network in aggregated_in_as):
                aggregated_networks.add(network)

    print(f"Maximum Aggregateable Prefixes: {max_agg_prefixes_count}")
    print(f"Unaggregateables Prefixes: {total_prefijos - max_agg_prefixes_count}")
    print(f"Factor de desagregación: {total_prefijos / len(aggregated_networks) if aggregated_networks else 0:.2f}")

    df['as_path_length'] = df['as_path'].apply(lambda x: len(clean_as_path(x)))
    print(f"Longest AS-Path: {df['as_path_length'].max()}")
    print(f"Average AS-Path: {df['as_path_length'].mean():.2f}")

    print(f"Realizando consultas whois...")
    unique_asns = list(df['origin_as'].drop_duplicates())
    tasks = [is_asn_registered(asn) for asn in unique_asns]
    results = await asyncio.gather(*tasks)

    unregistered_asns = {}
    for asn, registered in zip(unique_asns, results):
        if not registered:
            unregistered_asns[asn] = df[df['origin_as'] == asn]['prefix'].tolist()

    print(f"Total de ASNs no registrados: {len(unregistered_asns)}")
    print(f"Prefijos de ASNs no registrados: {sum(len(prefixes) for prefixes in unregistered_asns.values())}")

# Ejecutar el análisis asíncrono
asyncio.run(analyze_ipv6_prefixes(FILE_PATH))
