# Projecto de Sistemas de Elevada Confiabilidade #

## Primeira entrega ##

Grupo de SEConf 2

Luís Duarte 		79756 		luis.rafael.bastos.duarte@tecnico.ulisboa.pt

José Luís Pereira 	77925 		j.luis.pereira@tecnico.ulisboa.pt

Pedro Oliveira 		77956 		pedro.francisco.oliveira@tecnico.ulisboa.pt


-------------------------------------------------------------------------------

## Serviço Password Manager 

### Instruções de instalação 
*(Como colocar o projecto a funcionar numa máquina do laboratório)*

[0] Iniciar sistema operativo

Indicar Windows ou Linux
*(escolher um dos dois, que esteja disponível nos laboratórios)*


[1] Iniciar servidores de apoio

JUDDI:
> ./juddi-3.3.2_tomcat-7.0.64_9090/bin/startup.sh


[2] Criar KeyStore para clientes

JUDDI:
> keytool -genkey -alias client -keyalg RSA -keystore KeyStore.jks -keysize 2048



[3] Construir e executar **servidor**

> cd pm-ws_juddi/

> mvn clean package

> mvn exec:java


[4] Construir **cliente**

> cd pm-ws-cli_juddi/

> mvn clean package




-------------------------------------------------------------------------------

### Instruções de teste: ###
*(Como verificar que todas as funcionalidades estão a funcionar correctamente)*
CORRIGIR:

[1] Executar **cliente de testes  ao load**

> cd ~/Desktop/Grupo43/sd-store-cli

> mvn test  -Dtest=LoadIT



[2] Executar **cliente de testes  ao store**

> cd ~/Desktop/Grupo43/sd-store-cli

> mvn test  -Dtest=StoreIT




-------------------------------------------------------------------------------
**FIM**
