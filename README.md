# PytheM

Ferramenta de pentesting/network em pt-br desenvolvida em Python. A mesma está sendo desenvolvida com o intuito de que possa ser util a alguém e não me responsabilizo por nenhum uso indevido da mesma. Só funciona em sistemas operacionais GNU/Linux.

#Instalação

$sudo git clone https://github.com/m4n3dw0lf/PytheM/
$sudo pip install -r requirements.txt
$sudo ./pythem

#Features

[Brute-Force]:
  --bruter              Inicializa um ataque de força bruta, necessita de
                        wordlist.
  --service {ssh}       Serviço a ser atacado por força bruta. ex:
                        ./pythem.py -i wlan0 --bruter --service ssh -t
                        10.0.0.1 -f /usr/share/wordlist.txt -u username
  -u USERNAME, --username USERNAME
                        Usuário a ser utilizado no ataque de força bruta.

[Man-In-The-Middle]:
  --spoof               Redireciona tráfego usando ARPspoofing. ex:
                        './pythem.py -i wlan0 --spoof -g gateway --sniff
                        options'
  --arpmode {rep,req}   modo de ARPspoof: respostas(rep) ou requisições
                        (req) [padrão: rep].

[Remote]:
  --ssh                 Espera por uma conexão tcp reversa em SSH do alvo.
                        ex: ./pythem.py --ssh -l -p 7001
  -l [SERVER], --server [SERVER]
                        Endereço IP do servidor a escutar, padrão[0.0.0.0']
  -p [PORT], --port [PORT]
                        Porta do servidor a escutar, padrão=[7000]

[Sniffing]:
  --sniff               Habilita o sniffing de pacotes. ex: './pythem.py -i
                        wlan0 --sniff --filter manual
  --filter {all,dns,http,manual}
                        Modo de sniffing: all, dns, http ou manual
                        [padrão=all]. ex: './pythem.py -i wlan0 --spoof -g
                        192.168.1.1 --filter http'
  --pforensic           Lê arquivo .pcap e entra em shell interativo para
                        analise dos respectivos pacotes. ex: './pythem.py -i
                        wlan0 --rdpcap -f /path/file.pcap'.

[Scanning]:
  --scan                Faz scan em uma Range IP para descobrir hosts. ex:
                        './pythem.py -i wlan0 --scan -t 192.168.0.0/24 --mode
                        arp'.
  --mode {tcp,arp,manual}
                        Modo de scan: manual,tcp e arp padrão=[tcp].

[Utils]:
  --decode DECODE       Decodifica um texto com o padrão determinado. ex:
                        ./pythem.py -i wlan0 --decode base64
  --encode ENCODE       Codifica um texto com o padrão determinado. ex:
                        ./pythem.py -i wlan0 --encode hex
  --geoip               Determina aproximadamente a geolocalização do
                        endereço IP. ex:./pythem.py -i wlan0 --geoip --target
                        216.58.222.46

[Web]:
  --urlbuster           Inicializa teste de parametros em uma URL através de
                        uma wordlist. ex: ./pythem.py -i wlan0 --urlbuster -t
                        http://testphp.vulnweb.com/index.php?id= -f
                        /path/deUMaCEM.txt

[Wireless]:
  --startmon            Inicializa modo monitor na interface desejada. ex.
                        "./pythem.py -i wlan0 --startmon"
  --stopmon             Finaliza o modo monitor na interface préviamente
                        especificado. ex: "./pythem.py -i wlan0mon --stopmon"
  --ssid                Utiliza a interface em modo monitor para descobrir o
                        SSID de APs por perto.

By: m4n3dw0lf
