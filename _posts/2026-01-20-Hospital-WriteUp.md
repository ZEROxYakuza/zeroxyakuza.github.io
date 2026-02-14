## Hospital WriteUp - En Proceso...
Hospital es una máquina Windows de dificultad media que aloja un entorno Active Directory, un servidor web y una instancia RoundCube.

### Enumeración
Empezamos haciendo un simple ping a la máquina para probar la conectividad con la misma.

<img width="495" height="143" alt="imagen" src="https://github.com/user-attachments/assets/eb306cb8-cbfb-4985-a6a7-fa5c1af3d479" />

Y vemos que tenemos conexión sin problema.

Ahora vamos a realizar un escaneo de puertos con nmap y a extraer los puertos abiertos con extractPorts (función creada por s4vitar y facilitada a la comunidad). La función es la siguiente:

```sh
#!/bin/bash
# Used:
# nmap -p- --open -T5 -v -n ip -oG allPorts

# Extract nmap information
# Run as:
# extractPorts allPorts

function extractPorts(){
	# say how to usage
	if [ -z "$1" ]; then
		echo "Usage: extractPorts <filename>"
		return 1
	fi

	# Say file not found
	if [ ! -f "$1" ]; then
		echo "File $1 not found"
		return 1
	fi

	#if this not found correctly, you can delete it, from "if" to "fi".
	if ! grep -qE '^[^#].*/open/' "$1"; then
		echo "Format Invalid: Use -oG <file>, in nmap for a correct format."
		return 1
	fi

	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')";
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address"  >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -selection clipboard
	echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
	cat extractPorts.tmp; rm extractPorts.tmp
}
extractPorts "$1"
```

Así que vamos a ejecutar nmap con el comando:

```sh
nmap -v -n --min-rate 5000 -Pn -p- 10.129.4.219 -oG target
```

Y ahora usamos extractPorts con target:

<img width="1114" height="168" alt="imagen" src="https://github.com/user-attachments/assets/57384a1a-2b77-43b3-bb1d-c2fe09c7c0f2" />

Ya podemos usarl el siguiente comando:

```sh
nmap -v -n -sCV -p22,53,135,139,389,443,445,593,636,1801,2103,2105,2179,3268,3269,3389,6404,6406,6407,6409,6613,6622,6641,8080,9389 10.129.4.219 -oG ports_scan
```

Y vemos el resultado de lanzar scripts por defecto y escaneo de versiones a dichos puertos. También vemos el nombre del DC y por tanto, del dominio.

<img width="551" height="72" alt="imagen" src="https://github.com/user-attachments/assets/298d1a6a-c739-47f0-a4bb-99166f19a051" />

Incluiremos hospital.htb en nuestro /etc/hosts por si acaso necesitamos que se resuelva dicho nombre.

<img width="551" height="72" alt="imagen" src="https://github.com/user-attachments/assets/fed72464-5a8e-4a97-8319-63e351adf6e6" />


