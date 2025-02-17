import pandas as pd
import ipaddress
#Columnas
#0 -Type: Indica el formato.
#1- Marca de tiempo: Momento de la entrada en formato epoch.
#2 -W/A/B: Indica si se trata de una retirada (withdrawn), un anuncio (announcement) o una tabla de enrutamiento (routing table).
#3- Peer IP: Direcci´on IP del monitor.
#4 -Peer ASN: N´umero de Sistema Aut´onomo (ASN ) del monitor.
#5- Prefijo: Bloque de direcciones IP anunciado
#6- ASPath: Lista de AS atravesados para alcanzar el destino.
#7- Protocolo de origen: Usualmente IGP.
#8-Siguiente Hop: Direcci´on IP del siguiente salto.
#9- LocalPref: Preferencia local asignada a la ruta.
#10- MED: Discriminador de salida m´ultiple.
#11-Cadenas comunitarias: Valores comunitarios asociados a la ruta.
#12- Agregador at´omico: Indicador de rutas agregadas.
#13- Agregador: Informaci´on adicional sobre el agregador.

# Función vectorizada para verificar si una dirección es IPv6
def is_ipv6_vectorized(addresses):
    return addresses.str.strip().apply(lambda x: ipaddress.ip_network(x, strict=False).version == 6 if isinstance(x, str) else False)

# Lee solo las columnas necesarias del archivo
column_names = list(range(7))  # Asume 7 columnas; ajusta si es necesario
df = pd.read_csv('datos_rib.txt', delimiter='|', header=None, usecols=[5, 6], names=column_names)

# Aplica la función vectorizada para identificar IPv6
df['is_ipv6'] = is_ipv6_vectorized(df[5])

# Filtra direcciones IPv6 y elimina la columna temporal
filtered_df = df[df['is_ipv6']].drop(columns=['is_ipv6'])

# Guarda el resultado en un archivo de salida
filtered_df.to_csv('datos_columnas_filtradas.txt', sep='|', index=False, header=False)

print("El archivo de salida ha sido creado con los prefijos IPv6 ")
