# Guía de interpretación de STIX Patterns por tipo de observable

## Objetivo

Este documento organiza los patrones STIX por **tipo de observable** y explica, de forma útil para un analista o para otro agente de IA:

1. **Qué tipo de información intentan seleccionar o detectar**
2. **Qué observables y atributos STIX intervienen**
3. **Ejemplos concretos**, usando los patrones facilitados, con una explicación descriptiva de qué persigue cada uno

---

# 0. Observation Expression Qualifiers (seccion critica)

Esta seccion es especifica de los calificadores a nivel de observacion en STIX 2.1 y conviene leerla antes de usar logica temporal en reglas.

## Reglas semanticas de STIX 2.1

- Los qualifiers se aplican a una **observation expression** (o a una observation expression ya cualificada).
- Una observation expression **no puede tener mas de un qualifier del mismo tipo**.
- Qualifiers cubiertos aqui:
  - `REPEATS x TIMES`
  - `WITHIN x SECONDS`
  - `START t'...' STOP t'...'`

### `REPEATS x TIMES`

- Significa que la observation expression debe casar al menos `x` veces.
- Conceptualmente es un atajo para repetir la misma observation expression con `AND` (`x-1` veces adicionales).
- Importante: esto es cardinalidad sobre observaciones diferentes, no una copia textual del mismo predicado.

### `WITHIN x SECONDS`

- Todas las observaciones que casen con la expresion cualificada deben ocurrir dentro de la ventana temporal indicada.
- Semanticamente es una ventana de correlacion, no solo un filtro de campo.

### `START t'...' STOP t'...'`

- Selecciona observaciones con tiempo de observacion `>= START` y `< STOP`.
- Ambas fechas deben ir en literal timestamp STIX (`t'...'`).

## Baseline actual de SPUC (comportamiento runtime)

- `EQL`
  - `FOLLOWEDBY`: soportado via `sequence`.
  - `WITHIN` sobre `FOLLOWEDBY`: se baja a `sequence with maxspan=...`.
  - `REPEATS` en where-clause plano: solo advisory (normalmente baja a estado `partial`).
  - `WITHIN` en where-clause plano: solo advisory.
  - `START/STOP`: se mapea como filtro `@timestamp`.
- `KQL`
  - `START/STOP`: se mapea como filtro `Timestamp`.
  - `REPEATS` y `WITHIN` en where-clause plano: solo advisory.
  - `FOLLOWEDBY`: no soportado en baseline.
- `Sigma`
  - `REPEATS`: solo advisory en baseline.
  - `WITHIN` y `START/STOP`: no soportados en baseline.
  - `FOLLOWEDBY`: no soportado en baseline.
- `Snort`, `Suricata`, `YARA`
  - Observation qualifiers (`REPEATS/WITHIN/START STOP`) no soportados en baseline.

Nota: toma siempre la salida runtime (`runtime_status`, `summary`, `notes`) como fuente de verdad para fidelidad semantica.

---

# 0.1 Hashes y semantica de literales (referencia)

Esta seccion es explicita porque la interpretacion de hashes y literales impacta directamente la fidelidad semantica.

## Algoritmos de hash usados en patrones

- `MD5`
- `SHA-1`
- `SHA-256`
- `SHA-512`
- `SHA3-256`
- `SHA3-512`
- `SSDEEP`
- `TLSH`

Usa nombres exactos de algoritmo en paths como:

- `file:hashes.'SHA-256'`
- `artifact:hashes.MD5`

No trates algoritmos como intercambiables (`SHA-1` no es `SHA-256`).

## Formas literales y normalizacion

Literales STIX usados en la normalizacion de SPUC:

- `string`: `'texto'`
- `binary` (base64): `b'...'`
- `hex`: `h'...'`
- `timestamp`: `t'2016-06-01T00:00:00Z'`

Para `artifact:payload_bin`:

- Los strings planos se interpretan como bytes crudos.
- `b'...'` se decodifica de base64 a bytes.
- `h'...'` se decodifica como bytes hex.

No-equivalencia importante:

- `artifact:payload_bin = 'QUJD'` no es equivalente a `artifact:payload_bin = b'QUJD'`.

# 1. Detección sobre procesos (`process`)

Los patrones basados en `process` sirven para detectar **ejecución de programas, contexto de ejecución y relaciones entre procesos**. Son especialmente útiles para:

- Identificar procesos concretos o binarios conocidos
- Detectar líneas de comandos sospechosas
- Observar procesos creados en un rango temporal
- Detectar procesos ocultos
- Detectar procesos lanzados desde directorios anómalos
- Analizar qué proceso padre lanzó otro proceso
- Detectar secuencias de ejecución, como una acción seguida de otra en pocos segundos

## Observables y atributos implicados

### Observable principal
- `process`

### Atributos usados
- `process:pid`
- `process:is_hidden`
- `process:cwd`
- `process:created_time`
- `process:command_line`
- `process:name`
- `process:image_ref.name`
- `process:image_ref.hashes.'SHA-256'`
- `process:parent_ref.command_line`

### Qué información intentan escoger
- Identidad del proceso
- Ruta o contexto de ejecución
- Parámetros de ejecución
- Binario subyacente
- Hash del ejecutable
- Relación con el proceso padre
- Orden temporal entre procesos

## Ejemplos

### Identificación simple de procesos
- `[process:pid = 4]`  
  Busca el proceso con PID exacto `4`, normalmente útil para identificar un proceso concreto del sistema.

- `[process:pid > 1000]`  
  Busca procesos con PID alto, útil para acotar a procesos más recientes o no pertenecientes al núcleo básico del sistema.

- `[process:is_hidden = true]`  
  Intenta detectar procesos marcados como ocultos, lo que puede ser indicativo de evasión o comportamiento sospechoso.

- `[process:name = 'powershell.exe']`  
  Selecciona procesos cuyo nombre es exactamente `powershell.exe`.

- `[process:name = 'cmd.exe']`  
  Selecciona procesos cuyo nombre es exactamente `cmd.exe`.

- `[process:name LIKE '%.exe']`  
  Selecciona procesos cuyo nombre termina en `.exe`.

- `[process:name MATCHES '(?i)^powershell(\.exe)?$']`  
  Busca procesos cuyo nombre encaja exactamente con `powershell` o `powershell.exe`, sin distinguir mayúsculas de minúsculas.

### Binario asociado al proceso
- `[process:image_ref.name = 'powershell.exe']`  
  Busca procesos cuyo ejecutable referenciado se llama `powershell.exe`.

- `[process:image_ref.name LIKE '%.exe']`  
  Busca procesos cuyo binario asociado termina en `.exe`.

- `[process:image_ref.hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']`  
  Busca procesos cuyo ejecutable asociado tiene ese SHA-256 exacto, útil para cazar una muestra conocida.

### Contexto y metadatos de ejecución
- `[process:cwd LIKE 'C:\\Users\\%\\AppData\\%']`  
  Busca procesos ejecutados desde directorios bajo `AppData`, habitual en malware o binarios lanzados desde rutas de usuario.

- `[process:created_time >= t'2025-01-01T00:00:00Z']`  
  Busca procesos creados a partir de esa fecha.

### Líneas de comandos sospechosas
- `[process:command_line LIKE '%powershell%' AND process:command_line LIKE '%-enc%']`  
  Busca PowerShell con uso de argumentos codificados, muy típico en ofuscación.

- `[process:command_line LIKE '%rundll32%' AND process:command_line LIKE '%javascript:%']`  
  Busca uso de `rundll32` con `javascript:`, patrón clásico de abuso de LOLBins.

- `[process:command_line LIKE '%regsvr32%' AND process:command_line LIKE '%scrobj.dll%']`  
  Busca el abuso de `regsvr32` para cargar scripts o componentes de manera sospechosa.

- `[process:command_line LIKE '%mshta%' AND process:command_line LIKE '%http%']`  
  Busca `mshta` accediendo a recursos HTTP, útil para detectar ejecución remota de HTA o scripts.

- `[process:command_line LIKE '%certutil%' AND process:command_line LIKE '%-decode%']`  
  Busca uso de `certutil` para decodificar contenido, técnica habitual para reconstruir payloads.

- `[process:command_line LIKE '%powershell%' AND process:command_line LIKE '%DownloadString%']`  
  Busca PowerShell descargando contenido remoto mediante `DownloadString`.

- `[process:command_line MATCHES '(?i)^.*powershell(\.exe)?\s+.*DownloadString.*$']`  
  Variante más precisa mediante regex para detectar PowerShell con `DownloadString`.

- `[process:command_line LIKE '%cmd.exe%' AND process:command_line LIKE '%powershell%' AND process:command_line LIKE '%-w hidden%']`  
  Busca ejecución encadenada donde `cmd.exe` lanza PowerShell en modo oculto.

- `[process:command_line MATCHES '(?i)^.*cmd(\.exe)?\s+/c\s+.*powershell(\.exe)?\s+.*-w\s+hidden.*$']`  
  Variante regex más estructurada del caso anterior.

- `[process:command_line LIKE '%certutil%' AND process:command_line LIKE '%-urlcache%' AND process:command_line LIKE '%-f%' AND process:command_line LIKE '%.exe%']`  
  Busca uso de `certutil` para descargar forzadamente un `.exe`.

- `[process:command_line MATCHES '(?i)^.*certutil(\.exe)?\s+.*-urlcache\s+.*-f\s+.*https?://.+\s+.+\.exe.*$']`  
  Variante regex más exacta para descargas de ejecutables con `certutil`.

- `[process:command_line LIKE '%rundll32%' AND process:command_line LIKE '%javascript:%' AND process:command_line LIKE '%mshtml,RunHTMLApplication%']`  
  Busca el patrón clásico de ejecución de script vía `rundll32` y `RunHTMLApplication`.

- `[process:command_line MATCHES '(?i)^.*rundll32(\.exe)?\s+.*javascript:.*mshtml,RunHTMLApplication.*$']`  
  Versión regex más estricta del patrón anterior.

### Proceso padre
- `[process:parent_ref.command_line LIKE '%winword%']`  
  Busca procesos cuyo padre fue lanzado desde Word.

- `[process:parent_ref.command_line LIKE '%excel%']`  
  Busca procesos cuyo padre fue lanzado desde Excel.

- `[process:parent_ref.command_line LIKE '%outlook%']`  
  Busca procesos cuyo padre fue lanzado desde Outlook.

### Secuencias temporales
- `[process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachine Root$'] FOLLOWEDBY [process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachineTrustedPublisher$'] WITHIN 300 SECONDS`  
  Intenta detectar una secuencia de dos comandos relacionados con la instalación de certificados, ejecutados en un intervalo de 300 segundos.

---

# 2. Detección sobre claves de registro (`windows-registry-key`)

Los patrones sobre `windows-registry-key` permiten detectar **persistencia, configuración maliciosa, manipulación de servicios y cambios sospechosos en el registro de Windows**.

## Observables y atributos implicados

### Observable principal
- `windows-registry-key`

### Atributos usados
- `windows-registry-key:key`
- `windows-registry-key:modified_time`
- `windows-registry-key:number_of_subkeys`
- `windows-registry-key:values[*].name`
- `windows-registry-key:values[*].data`
- `windows-registry-key:values[*].data_type`

### Qué información intentan escoger
- Nombre exacto de la clave
- Jerarquía de clave o familia de claves
- Fecha de modificación
- Número de subclaves
- Nombres de valores del registro
- Datos contenidos en los valores
- Tipo de dato almacenado

## Ejemplos

- `[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\CryptoLocker\\Files']`  
  Busca una clave concreta asociada con CryptoLocker.

- `[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\\CryptoLocker_0388']`  
  Busca una entrada exacta de persistencia en `Run`.

- `[windows-registry-key:key LIKE 'HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\\%']`  
  Busca cualquier clave bajo `Run`, útil para persistencia de inicio.

- `[windows-registry-key:key MATCHES '^HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet\\\\Services\\\\.+$']`  
  Busca claves de servicios en HKLM, útil para detectar servicios creados o alterados.

- `[windows-registry-key:modified_time >= t'2025-01-01T00:00:00Z']`  
  Busca claves modificadas a partir de esa fecha.

- `[windows-registry-key:number_of_subkeys > 10]`  
  Busca claves con muchas subclaves, útil para estructura inusual o compleja.

- `[windows-registry-key:values[*].name = 'Start']`  
  Busca valores llamados `Start`, relevantes en configuración de servicios.

- `[windows-registry-key:values[*].name = 'ImagePath']`  
  Busca valores `ImagePath`, relevantes para binarios asociados a servicios.

- `[windows-registry-key:values[*].data LIKE '%powershell%']`  
  Busca valores del registro que contengan referencias a PowerShell.

- `[windows-registry-key:values[*].data LIKE '%rundll32%']`  
  Busca referencias a `rundll32` en datos del registro.

- `[windows-registry-key:values[*].data_type = 'REG_SZ']`  
  Busca valores de tipo cadena.

- `[windows-registry-key:values[*].data_type = 'REG_DWORD']`  
  Busca valores DWORD.

- `[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\CryptoLocker\\Files' OR windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\\CryptoLocker_0388']`  
  Busca una de dos claves concretas asociadas a un mismo contexto malicioso.

- `[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%' AND windows-registry-key:values[*].data LIKE '%.exe%']`  
  Busca persistencia en `Run` que apunte a ejecutables.

---

# 3. Detección sobre tráfico de red (`network-traffic`)

Los patrones con `network-traffic` permiten detectar **comunicaciones entre origen y destino, protocolos usados, puertos implicados y relaciones de red**. Son la forma más rica de expresar telemetría de red en STIX.

## Observables y atributos implicados

### Observable principal
- `network-traffic`

### Atributos usados
- `network-traffic:src_ref.type`
- `network-traffic:src_ref.value`
- `network-traffic:dst_ref.type`
- `network-traffic:dst_ref.value`
- `network-traffic:src_port`
- `network-traffic:dst_port`
- `network-traffic:protocols`

### Qué información intentan escoger
- Tipo de origen o destino (IP, dominio)
- Dirección IP o valor del destino/origen
- Puertos de origen y destino
- Protocolo observado
- Secuencias repetidas
- Inclusión de una IP dentro de un rango CIDR (`ISSUBSET`)

## Ejemplos

- `[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']`  
  Busca tráfico cuyo destino es una dirección IPv4 concreta.

- `[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 5 TIMES WITHIN 1800 SECONDS`  
  Intenta detectar cinco repeticiones de tráfico hacia `example.com` dentro de 30 minutos.

- `[network-traffic:protocols = 'udp' AND network-traffic:dst_port = 53]`  
  Busca tráfico UDP hacia el puerto 53, típico de DNS.

- `[network-traffic:src_ref.value = '10.0.0.5' AND network-traffic:dst_ref.value = '203.0.113.10' AND network-traffic:dst_port = 443 AND network-traffic:protocols = 'tcp']`  
  Busca una comunicación TCP concreta desde una IP origen hacia una IP destino en 443.

- `[network-traffic:src_port >= 1024 AND network-traffic:dst_port <= 1024]`  
  Busca patrones donde el puerto origen es alto y el destino es bajo, útil para cliente-servidor o conexiones salientes a servicios conocidos.

- `[network-traffic:src_ref.value ISSUBSET '10.0.0.0/8' AND network-traffic:protocols = 'tcp']`  
  Busca tráfico TCP cuyo origen pertenece al rango privado `10.0.0.0/8`.

- `[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value ISSUBSET '203.0.113.0/24']`  
  Busca tráfico dirigido a una IP dentro de ese rango CIDR.

- `[network-traffic:dst_ref.value LIKE '192.168.%']`  
  Busca tráfico cuyo destino parece pertenecer a una red privada `192.168.x.x`.

- `[network-traffic:protocols = 'http']`  
  Busca tráfico etiquetado como HTTP.

---

# 4. Detección sobre observables de red independientes

Estos patrones trabajan sobre observables de red **sin el contexto completo de una conexión**. Son útiles para representar indicadores sueltos: una IP, un dominio, una URL o una MAC.

## Observables y atributos implicados

### Observables
- `ipv4-addr`
- `ipv6-addr`
- `domain-name`
- `url`
- `mac-addr`

### Atributos usados
- `ipv4-addr:value`
- `ipv6-addr:value`
- `domain-name:value`
- `domain-name:resolves_to_refs[*].value`
- `url:value`
- `mac-addr:value`

### Qué información intentan escoger
- IP exacta
- Rango CIDR
- Dominio exacto o patrón de subdominios
- URL exacta o patrón de ruta
- Dirección MAC exacta

---

## 4.1 IPv4

### Ejemplos
- `[ipv4-addr:value = '8.8.8.8']`  
  Busca una IP concreta.

- `[ipv4-addr:value ISSUBSET '198.51.100.0/24']`  
  Intenta detectar IPs que pertenezcan a ese bloque CIDR.

- `[ipv4-addr:value ISSUBSET '10.0.0.0/8']`  
  Intenta detectar IPs dentro del rango privado `10.0.0.0/8`.

- `[ipv4-addr:value = '198.51.100.0/24']`  
  Busca exactamente ese valor, expresado como bloque CIDR.

- `[ipv4-addr:value = '127.0.0.1']`  
  Busca la dirección de loopback.

## 4.2 IPv6

### Ejemplos
- `[ipv6-addr:value ISSUBSET '2001:db8::/32']`  
  Intenta detectar direcciones IPv6 dentro de ese prefijo.

- `[ipv6-addr:value = '2001:db8::/96']`  
  Busca exactamente ese bloque IPv6.

## 4.3 Dominios

### Ejemplos
- `[domain-name:value = 'evil.example']`  
  Busca un dominio concreto.

- `[domain-name:value ISSUBSET 'evil.example']`  
  Intenta expresar una relación de subconjunto sobre dominio, aunque conceptualmente esta semántica no suele encajar bien con dominios.

- `[domain-name:value LIKE '%.example.com']`  
  Busca subdominios de `example.com`.

- `[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']`  
  Intenta relacionar un dominio con una IP a la que resolvería.

## 4.4 URLs

### Ejemplos
- `[url:value = 'http://example.com/login']`  
  Busca una URL exacta.

- `[url:value != 'http://example.com/logout']`  
  Excluye una URL concreta.

- `[url:value LIKE 'https://%/api/%']`  
  Busca URLs HTTPS que contengan `/api/`.

- `[url:value MATCHES '^https://[^/]+/admin/.*$']`  
  Busca URLs HTTPS cuya ruta esté bajo `/admin/`.

- `[url:value = 'http://example.com/foo' OR url:value = 'http://example.com/bar']`  
  Busca una de dos URLs concretas.

- `[url:value ISSUBSET 'https://example.com/']`  
  Intenta expresar una relación de subconjunto sobre URL, aunque semánticamente no suele ser el operador más adecuado para este tipo de observable.

## 4.5 MAC

### Ejemplos
- `[mac-addr:value = 'd2:fb:49:24:37:18']`  
  Busca una dirección MAC exacta.

- `[mac-addr:value ISSUBSET 'd2:fb:49:24:37:18']`  
  Intenta usar `ISSUBSET` sobre una MAC, lo cual no suele tener sentido semántico como subconjunto.

---

# 5. Detección sobre cuentas de usuario (`user-account`)

Los patrones sobre `user-account` sirven para detectar **cuentas concretas, tipos de cuenta y combinaciones de atributos de identidad**.

## Observables y atributos implicados

### Observable principal
- `user-account`

### Atributos usados
- `user-account:account_type`
- `user-account:user_id`
- `user-account:account_login`

### Qué información intentan escoger
- Tipo de cuenta
- Identificador interno
- Nombre de inicio de sesión
- Conjuntos concretos de usuarios

## Ejemplos

- `[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter']`  
  Busca una cuenta Unix concreta con UID y login específicos.

- `[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']`  
  Intenta detectar simultáneamente tres cuentas concretas dentro de una misma expresión lógica.

---

# 6. Detección sobre correos electrónicos (`email-message`)

Los patrones sobre `email-message` sirven para detectar **correos concretos por remitente, asunto u otras propiedades de mensaje**.

## Observables y atributos implicados

### Observable principal
- `email-message`

### Atributos usados
- `email-message:sender_ref.value`
- `email-message:subject`

### Qué información intentan escoger
- Remitente exacto
- Tema o asunto de un correo

## Ejemplos

- `[email-message:sender_ref.value = 'jdoe@example.com' AND email-message:subject = 'Conference Info']`  
  Busca correos enviados por `jdoe@example.com` con asunto `Conference Info`.

---

# 7. Detección sobre directorios (`directory`)

Los patrones sobre `directory` sirven para detectar **rutas de directorio sensibles, directorios temporales, carpetas de usuario, rutas de sistema y cambios temporales sobre directorios**.

## Observables y atributos implicados

### Observable principal
- `directory`

### Atributos usados
- `directory:path`
- `directory:mtime`

### Qué información intentan escoger
- Ruta exacta del directorio
- Coincidencia por patrón de ruta
- Directorios modificados a partir de una fecha

## Ejemplos

- `[directory:path = 'C:\\Windows\\System32']`  
  Busca el directorio exacto `C:\Windows\System32`.

- `[directory:path LIKE 'C:\\Users\\%\\AppData\\Local\\Temp%']`  
  Busca directorios temporales de usuarios en Windows.

- `[directory:path MATCHES '(?i)^/home/[^/]+/\\.ssh/?$']`  
  Busca directorios `.ssh` en home de usuarios Linux.

- `[directory:mtime >= t'2025-01-01T00:00:00Z' AND directory:path LIKE '/var/log/%']`  
  Busca directorios bajo `/var/log/` modificados desde esa fecha.

- `[directory:path LIKE 'C:\\Windows\\Tasks%' AND directory:mtime > t'2025-01-01T00:00:00Z']`  
  Busca directorios bajo `C:\Windows\Tasks` con modificación posterior a esa fecha.

---

# 8. Detección sobre sistemas autónomos (`autonomous-system`)

Los patrones sobre `autonomous-system` sirven para seleccionar **ASN concretos, nombres de proveedores, RIR asociados o rangos de numeración**. Son útiles para caracterizar infraestructura de red.

## Observables y atributos implicados

### Observable principal
- `autonomous-system`

### Atributos usados
- `autonomous-system:number`
- `autonomous-system:name`
- `autonomous-system:rir`

### Qué información intentan escoger
- Número de ASN
- Nombre del sistema autónomo
- Registro regional asociado (RIR)

## Ejemplos

- `[autonomous-system:number = 13335]`  
  Busca un ASN concreto.

- `[autonomous-system:number > 64511]`  
  Busca ASN por encima de ese umbral.

- `[autonomous-system:name = 'Cloudflare, Inc.']`  
  Busca un sistema autónomo por nombre exacto.

- `[autonomous-system:name LIKE '%Google%']`  
  Busca ASN cuyo nombre contenga `Google`.

- `[autonomous-system:rir = 'ARIN']`  
  Busca ASN asociados a ARIN.

- `[autonomous-system:number > 64511 AND autonomous-system:rir = 'RIPE']`  
  Busca ASN altos dentro del ámbito de RIPE.

- `[autonomous-system:name MATCHES '^(?i)(cloudflare|google|microsoft).*$']`  
  Busca ASN cuyo nombre empiece por Cloudflare, Google o Microsoft, ignorando mayúsculas/minúsculas.

---

# 9. Detección sobre archivos (`file`)



Los patrones sobre `file` sirven para detectar **nombres de archivo sospechosos, extensiones maliciosas, tamaños inusuales, fechas relevantes y hashes conocidos**.

## Observables y atributos implicados

### Observable principal
- `file`

### Atributos usados
- `file:name`
- `file:ctime`
- `file:atime`
- `file:mtime`
- `file:size`
- `file:hashes.'SHA-256'`
- `file:hashes.'SHA-1'`

### Qué información intentan escoger
- Nombre exacto o por patrón
- Extensión de archivo
- Fecha de creación, acceso o modificación
- Tamaño
- Hash conocido o excluido

## Ejemplos

### Archivos concretos
- `[file:name = 'cmd.exe']`  
  Busca el archivo `cmd.exe`.

- `[file:name = 'invoice.pdf' AND file:size > 200000]`  
  Busca un `invoice.pdf` de tamaño significativo.

- `[file:name = 'setup.exe']` junto con un hash excluido  
  Busca un `setup.exe` cuyo SHA-1 no sea uno concreto.

### Fechas
- `[file:ctime = t'2024-10-01T08:30:00Z']`  
  Busca archivos creados en esa fecha exacta.

- `[file:atime >= t'2025-01-01T00:00:00Z']`  
  Busca archivos accedidos desde esa fecha.

- `[file:mtime >= t'2025-01-01T00:00:00Z' AND file:mtime < t'2026-01-01T00:00:00Z']`  
  Busca archivos modificados dentro de ese rango temporal.

- `[file:name != 'readme.txt' AND file:ctime < t'2023-01-01T00:00:00Z']`  
  Excluye `readme.txt` y busca archivos más antiguos.

### Tamaño
- `[file:size > 1048576]`  
  Busca archivos mayores de 1 MB.

- `[file:size <= 512000]`  
  Busca archivos pequeños o medianos.

- `[file:size >= 20000 AND file:size <= 40000 AND file:name LIKE '%.lnk']`  
  Busca accesos directos `.lnk` en un rango de tamaño concreto.

- `[file:name LIKE '%backup%' AND file:ctime >= t'2025-02-01T00:00:00Z' AND file:size > 10485760]`  
  Busca archivos grandes tipo backup creados recientemente.

### Patrones de nombre
- `[file:name LIKE '%.exe']`  
  Busca ejecutables.

- `[file:name LIKE 'invoice_%']`  
  Busca archivos cuyo nombre empieza por `invoice_`.

- `[file:name LIKE '%.docm']`  
  Busca documentos Word con macros.

- `[file:name MATCHES '^invoice_[0-9]{4}\\.pdf$']`  
  Busca PDFs con convención `invoice_####.pdf`.

- `[file:name MATCHES '^(update|patch|hotfix).+\\.(exe|msi)$']`  
  Busca ejecutables o instaladores disfrazados de actualización.

- `[file:name != 'svchost.exe' AND file:name MATCHES '^svchost\\.[a-z0-9]{2,4}\\.exe$']`  
  Busca archivos que imitan a `svchost.exe` con sufijos sospechosos.

- `[file:name LIKE '%.pdf.exe' AND file:size < 500000]`  
  Busca dobles extensiones, típico de engaño al usuario.

- `[file:name MATCHES '^report.+\\.(exe|scr)$' AND file:ctime > t'2024-01-01T00:00:00Z']`  
  Busca ficheros `report*` con extensión ejecutable creados recientemente.

### Hashes
- `[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file:name LIKE '%.pdf']`  
  Busca un archivo con hash conocido que además se presenta como PDF.

- `[file:hashes.'SHA-1' != '3395856ce81f2b7382dee72602f798b642f14140' AND file:name = 'setup.exe']`  
  Busca un `setup.exe` cuyo hash no coincide con el esperado, útil para integridad o suplantación.

---

# 10. Resumen práctico para analistas y agentes

## Qué se puede expresar bien con estos patrones

Los patrones facilitados cubren especialmente bien:

- **Procesos y línea de comandos**
- **Registro de Windows**
- **Archivos**
- **Rutas de directorios**
- **Identidades de usuario**
- **Red con contexto de conexión (`network-traffic`)**
- **Indicadores sueltos de red (IP, dominios, URLs, MAC)**
- **Mensajes de correo**
- **Infraestructura de red por ASN**

## Qué tipo de lógica aparece

Los ejemplos usan varias familias de lógica de detección:

- **Igualdad exacta**: `=`
- **Desigualdad**: `!=`
- **Comparaciones numéricas o temporales**: `>`, `>=`, `<`, `<=`
- **Patrones simples**: `LIKE`
- **Expresiones regulares**: `MATCHES`
- **Rangos CIDR o inclusión en red**: `ISSUBSET`
- **Combinación de condiciones**: `AND`, `OR`
- **Secuencias temporales**: `FOLLOWEDBY`
- **Frecuencia temporal**: `REPEATS ... WITHIN ...`

## Recomendación conceptual

Para un analista o un agente de IA, la mejor forma de entender estos patrones es leerlos como:

- **Qué observable están mirando**
- **Qué atributo del observable están filtrando**
- **Qué operador usan**
- **Qué comportamiento operativo quieren representar**

Por ejemplo:

- `process:command_line` suele expresar **comportamiento de ejecución**
- `windows-registry-key:key` suele expresar **persistencia o configuración**
- `network-traffic:*` suele expresar **comunicación**
- `file:name`, `file:size`, `file:hashes.*` suelen expresar **artefactos**
- `user-account:*` suele expresar **identidad**
- `directory:path` suele expresar **ubicación sensible**
- `autonomous-system:*` suele expresar **contexto de infraestructura**

---
