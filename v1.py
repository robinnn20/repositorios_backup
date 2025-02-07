import ipaddress
import pandas as pd

class PatriciaTrieNode:
    #El método __init__ es el constructor de la clase. Este método se ejecuta automáticamente cuando se crea una nueva instancia de PatriciaTrieNode.
    def __init__(self):
        self.children = {} #    Esta línea crea un diccionario vacío llamado children. En un trie, cada nodo puede tener varios "hijos", donde cada hijo representa un prefijo adicional del valor que se está almacenando.
        self.network = None  # Guarda la red si el nodo es un prefijo válido
        self.is_aggregated = False  # Marca si el prefijo ya fue combinado

class PatriciaTrie:
    #En este caso, se está inicializando un objeto de la clase con un nodo raíz (root) que es un PatriciaTrieNode.
    def __init__(self):
        self.root = PatriciaTrieNode() #Aquí se crea un nodo raíz para la estructura de datos Patricia Trie
#La función insert agrega una red (objeto network) a un Patricia Trie. Comienza desde el nodo raíz del trie y convierte la dirección de red (network_address) en una cadena binaria,
#recortándola según la longitud del prefijo (prefixlen). Luego, recorre cada bit de esa cadena binaria,
#creando nodos nuevos en el trie si no existen para ese bit.
#Finalmente, cuando alcanza el final del prefijo, asigna el objeto network al nodo correspondiente, asociando la red con ese nodo del trie.
#Este proceso organiza las redes de manera eficiente, 
#facilitando la búsqueda y almacenamiento de direcciones.
    def insert(self, network):
        #Se empieza desde el nodo raíz del trie, representado por self.root.
        node = self.root
        prefix_str = bin(int(network.network_address))[2:].zfill(128)[:network.prefixlen]
        
        for bit in prefix_str:
            if bit not in node.children:
                node.children[bit] = PatriciaTrieNode()
            node = node.children[bit]
        
        node.network = network


#Esta función tiene como objetivo determinar si el prefijo de una red (network) es parte de una supernet (una red más grande que la contiene) o si está contiguo a otro prefijo en el trie.
    def find_supernet_or_contiguous(self, network):

        node = self.root #Comienza la búsqueda desde el nodo raíz del trie.

        #Convierte la dirección de red (network.network_address) en una cadena binaria de 128 bits (esto es útil para IPv6). El prefijo no se recorta aquí porque se necesita la dirección completa para buscar contigüidad.
        prefix_str = bin(int(network.network_address))[2:].zfill(128) 

        #Inicializa una variable para guardar una posible supernet si se encuentra durante la búsqueda.
        supernet_candidate = None

        # Busca en el trie mientras sea posible 
        #recorre la dirección binaria (prefix_str) bit por bit.
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
            #Calcula la dirección contigua a la red dada (next_prefix), sumando 1 << (128 - network.prefixlen) a su dirección. Esto representa la dirección inmediatamente siguiente al rango del prefijo actual.
            next_prefix = network.network_address + (1 << (128 - network.prefixlen))

            #Si la dirección de red del nodo actual coincide con la dirección contigua (node.network.network_address == next_prefix), significa que la red es adyacente a la red dada, y se devuelve este nodo.
            if node.network.network_address == next_prefix:
                return node.network

        return supernet_candidate




   #El propósito de esta función es marcar un nodo del trie como agregado (is_aggregated = True) para una red específica (network)
    def mark_as_aggregated(self, network):
        node = self.root

        #Convierte la dirección de red (network.network_address) en una cadena binaria de 128 bits y la recorta a la longitud del prefijo ([:network.prefixlen]). Esto garantiza que solo se trabaje con los bits relevantes del prefijo.
        prefix_str = bin(int(network.network_address))[2:].zfill(128)[:network.prefixlen]
        #Recorre el trie siguiendo cada bit del prefijo binario (prefix_str).
        for bit in prefix_str:
            node = node.children[bit]

        #Verifica si el nodo encontrado contiene exactamente la red dada (network).
        if node.network == network:
            node.is_aggregated = True


def analyze_ipv6_prefixes(file_path):
    # Carga el archivo y parsea los prefijos
    df = pd.read_csv(file_path, delimiter='|', header=None, names=["prefix", "as_path"])
    df['network'] = df['prefix'].apply(lambda x: ipaddress.ip_network(x.strip(), strict=False))
    df['origin_as'] = df['as_path'].apply(lambda x: x.split()[-1])

    #Se crea una instancia de la clase PatriciaTrie, que representará la estructura del trie donde se almacenarán los prefijos de red.
    trie = PatriciaTrie()
    for network in df['network'].drop_duplicates():
        #Inserta cada red única en el trie usando el método insert. Este método recorre el prefijo de la red bit a bit y lo almacena en la estructura del trie
        trie.insert(network)

    
    #Se calcula la cantidad de redes únicas.
    total_prefijos = len(df['network'].drop_duplicates())
    print(f"Total de prefijos únicos: {total_prefijos}")

    #Para cada red única, se accede a la longitud de su prefijo. Por ejemplo:
    #Para 192.168.0.0/24, la longitud del prefijo es 24.
    #Para 10.0.0.0/8, la longitud del prefijo es 8.
    #Con los datos de la longitud finalmente converge en una suma hecha por la funcion sum().
    total_prefix_length = sum(network.prefixlen for network in df['network'].drop_duplicates())
    #Calcula el promedio de las longitudes de los prefijos únicos.
    #Si no hay prefijos únicos (total_prefijos = 0), evita dividir por cero y asigna 0 al promedio.
    average_prefix_length = total_prefix_length / total_prefijos if total_prefijos else 0
    print(f"Average Prefix Length: {average_prefix_length:.2f}")

    #Inicializa un contador para llevar el registro de cuántos prefijos han sido agregado
    max_agg_prefixes_count = 0
    #Es un conjunto que guarda los prefijos que ya han sido marcados como agregados. Esto evita procesar nuevamente los mismos prefijos.
    aggregated_networks = set()

    # Ahora comparamos todos los prefijos sin restricción de AS de origen
    #Se itera sobre todos los prefijos únicos de la columna network del DataFrame y la funcion  df.drop_duplicates() asegura que solo se procesen prefijos únicos, eliminando duplicados
    for network in df['network'].drop_duplicates():

        #Verifica si el prefijo actual (network) ya está en el conjunto aggregated_networks.
        #Si el prefijo ya fue procesado previamente (por haber sido identificado como parte de una supernet o un prefijo contiguo), lo salta y pasa al siguiente prefijo
        if network in aggregated_networks:
            continue
            
        #Busca si el prefijo actual (network) es parte de una supernet o está contiguo a otro prefijo en el trie.
        supernet_or_contiguous = trie.find_supernet_or_contiguous(network)
        #Verifica si se encontró una supernet o prefijo contiguo para el prefijo actual. Si sí, ejecuta las siguientes acciones:
        if supernet_or_contiguous:
            #Incrementa el contador de prefijos agregados, ya que se ha encontrado una supernet o un prefijo contiguo válido.
            max_agg_prefixes_count += 1
            #Marca el prefijo actual como agregado, añadiéndolo al conjunto aggregated_networks.
            aggregated_networks.add(network)
            #Llama al método mark_as_aggregated para marcar el nodo correspondiente al prefijo actual (network) en el trie como agregado. Esto evita procesar el prefijo nuevamente en el futuro.
            trie.mark_as_aggregated(network)
            #Agrega también la supernet o el prefijo contiguo encontrado al conjunto aggregated_networks. Esto asegura que estos prefijos no se procesen nuevamente en iteraciones futuras.
            aggregated_networks.add(supernet_or_contiguous)

    print(f"Maximum Aggregateable Prefixes: {max_agg_prefixes_count}")
    #Se calcula restando el número de prefijos agregados (max_agg_prefixes_count) del total de prefijos únicos (total_prefijos).
    #Esto da como resultado la cantidad de prefijos no agregables, es decir, aquellos que no pudieron ser agrupados como parte de una supernet o como prefijos contiguos.
    non_agg_prefixes_count = total_prefijos - max_agg_prefixes_count
    print(f"Unaggregateables Prefixes: {non_agg_prefixes_count}")
    
    #se procede a calcular cuántos sistemas autónomos (AS) hay en la ruta de cada prefijo.
    df['as_path_length'] = df['as_path'].apply(lambda x: len(x.split()))
    #Encuentra el valor máximo en la columna as_path_length.
    #Este valor representa la longitud más larga de cualquier ruta AS en el conjunto de datos.
    longest_as_path = df['as_path_length'].max()
    #Calcula el promedio de los valores en la columna as_path_length.
    #Esto da como resultado la longitud promedio de las rutas AS en el conjunto de datos.
    average_as_path_length = df['as_path_length'].mean()

    print(f"Longest AS-Path: {longest_as_path}")
    print(f"Average AS-Path: {average_as_path_length:.2f}")


file_path = 'datos_columnas_filtradas.txt'
analyze_ipv6_prefixes(file_path)
