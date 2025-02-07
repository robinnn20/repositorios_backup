import ipaddress
import pandas as pd

class PatriciaTrieNode:
    def __init__(self):
        self.children = {}
        self.network = None  # Guarda la red si el nodo es un prefijo válido
        self.is_aggregated = False  # Marca si el prefijo ya fue combinado

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
        """Busca si el prefijo dado pertenece a una supernet o es contiguo a otro prefijo."""
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)
        supernet_candidate = None

        # Busca en el trie mientras sea posible
        for bit in prefix_str:
            if bit in node.children:
                node = node.children[bit]
                if node.network and node.network.prefixlen < network.prefixlen:
                    # Si encuentra una supernet, la guarda como candidata
                    supernet_candidate = node.network
            else:
                break

        # Verifica si es contiguo a otro prefijo en el mismo nivel
        if node and node.network:
            next_prefix = network.network_address + (1 << (128 - network.prefixlen))
            if node.network.network_address == next_prefix:
                return node.network

        return supernet_candidate

    def mark_as_aggregated(self, network):
        """Marca un prefijo como agregado."""
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)[:network.prefixlen]
        for bit in prefix_str:
            node = node.children[bit]
        if node.network == network:
            node.is_aggregated = True


def analyze_ipv6_prefixes(file_path):
    # Carga el archivo y parsea los prefijos
    df = pd.read_csv(file_path, delimiter='|', header=None, names=["prefix", "as_path"])
    df['network'] = df['prefix'].apply(lambda x: ipaddress.ip_network(x.strip(), strict=False))
    df['origin_as'] = df['as_path'].apply(lambda x: x.split()[-1])

    # Creación de un trie para almacenar los prefijos
    trie = PatriciaTrie()

    # Diccionario para almacenar los prefijos por AS de origen
    as_prefixes = {}

    # Insertar los prefijos en el trie y agrupar por AS
    for index, row in df.iterrows():
        network = row['network']
        origin_as = row['origin_as']
        if origin_as not in as_prefixes:
            as_prefixes[origin_as] = []
        as_prefixes[origin_as].append(network)
        trie.insert(network)

    # Variables para el análisis
    total_prefijos = len(df['network'].drop_duplicates())
    print(f"Total de prefijos únicos: {total_prefijos}")

    total_prefix_length = sum(network.prefixlen for network in df['network'].drop_duplicates())
    average_prefix_length = total_prefix_length / total_prefijos if total_prefijos else 0
    print(f"Average Prefix Length: {average_prefix_length:.2f}")

    max_agg_prefixes_count = 0
    aggregated_networks = set()

    # Procesamiento de cada AS de origen
    for origin_as, networks in as_prefixes.items():
        networks = sorted(set(networks), key=lambda x: (x.prefixlen, x.network_address))
        current_aggregated = []

        # Procesar los prefijos de un AS
        for network in networks:
            if network in aggregated_networks:
                continue

            # Buscar una supernet o contiguo solo dentro del mismo AS
            supernet_or_contiguous = trie.find_supernet_or_contiguous(network)
            if supernet_or_contiguous:
                # Si se encuentra una supernet o contiguo, agregamos ambos
                max_agg_prefixes_count += 1
                aggregated_networks.add(network)
                aggregated_networks.add(supernet_or_contiguous)
                trie.mark_as_aggregated(network)
                trie.mark_as_aggregated(supernet_or_contiguous)

        # Guardar el estado de agregación para este AS
        current_aggregated.extend([network for network in networks if network in aggregated_networks])

    print(f"Maximum Aggregateable Prefixes: {max_agg_prefixes_count}")

    # Calcular los prefijos no agregables
    non_agg_prefixes_count = total_prefijos - max_agg_prefixes_count
    print(f"Unaggregateables Prefixes: {non_agg_prefixes_count}")

    # Análisis de AS-path
    df['as_path_length'] = df['as_path'].apply(lambda x: len(x.split()))
    longest_as_path = df['as_path_length'].max()
    average_as_path_length = df['as_path_length'].mean()

    print(f"Longest AS-Path: {longest_as_path}")
    print(f"Average AS-Path: {average_as_path_length:.2f}")


# Ejemplo de uso
file_path = 'datos_columnas_filtradas.txt'
analyze_ipv6_prefixes(file_path)
