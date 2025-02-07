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


def clean_as_path(as_path):
    """Limpia el as_path de caracteres innecesarios como `{}`, `,`."""
    # Remueve `{`, `}`, y `,` y separa el string en los AS individuales
    cleaned = as_path.replace("{", "").replace("}", "").replace(",", " ").split()
    return cleaned

def analyze_ipv6_prefixes(file_path):
    # Carga el archivo y parsea los prefijos
    df = pd.read_csv(file_path, delimiter='|', header=None, names=["prefix", "as_path"])
    df['network'] = df['prefix'].apply(lambda x: ipaddress.ip_network(x.strip(), strict=False))
    # Limpia el AS path
    df['origin_as'] = df['as_path'].apply(lambda x: clean_as_path(x)[-1])  # Último AS es el origen

    trie = PatriciaTrie()
    for network in df['network'].drop_duplicates():
        trie.insert(network)

    total_prefijos = len(df['network'].drop_duplicates())
    print(f"Total de prefijos únicos: {total_prefijos}")

    total_prefix_length = sum(network.prefixlen for network in df['network'].drop_duplicates())
    average_prefix_length = total_prefix_length / total_prefijos if total_prefijos else 0
    print(f"Average Prefix Length: {average_prefix_length:.2f}")

    grouped_as = df.groupby('origin_as')
    max_agg_prefixes_count = 0
    aggregated_networks = set()

    # Mejora en la agrupación de prefijos por AS y optimización del cálculo de agregación
    for origin_as, group in grouped_as:
        networks = sorted(group['network'].drop_duplicates().tolist(), key=lambda x: (x.prefixlen, x.network_address))
        aggregated_in_as = set()

        # Barrido eficiente de redes por AS
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

        # Actualiza el conteo de redes agregadas en el AS
        aggregated_networks.update(aggregated_in_as)

    print(f"Maximum Aggregateable Prefixes: {max_agg_prefixes_count}")

    non_agg_prefixes_count = total_prefijos - max_agg_prefixes_count
    print(f"Unaggregateables Prefixes: {non_agg_prefixes_count}")

    # Calcular los prefijos totales anunciados (incluyendo repeticiones)
    total_prefijos_anunciados = len(df)
    print(f"Total de Prefijos Anunciados (con repeticiones): {total_prefijos_anunciados}")

    # Cálculo del factor de desagregación
    factor_desagregacion = total_prefijos / len(aggregated_networks) if len(aggregated_networks) else 0
    print(f"Factor de desagregación: {factor_desagregacion:.2f}")

    df['as_path_length'] = df['as_path'].apply(lambda x: len(clean_as_path(x)))
    longest_as_path = df['as_path_length'].max()
    average_as_path_length = df['as_path_length'].mean()

    print(f"Longest AS-Path: {longest_as_path}")
    print(f"Average AS-Path: {average_as_path_length:.2f}")


# Ejemplo de uso
file_path = 'datos_columnas_filtradas.txt'
analyze_ipv6_prefixes(file_path)
