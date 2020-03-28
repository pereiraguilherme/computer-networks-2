# Final exercise of Computer Networks 2
##### Trabalho sobre protocolo IPV6 e TCP da disciplina/cadeira de Redes 2. 

#### Configuracao:

Para rodar o projeto e preciso configurar algumas coisas no arquivo send_functions.py.
O primeiro e o endereco MAC da maquina. Para isso segue descricao abaixo:
    
    sudo apt install net-tools
    sudo ifconfig
    
Apos, configurar ip de destino e ip de origem. Para rodar ainda precisamos passar argumentos sendo eles:


| Argumento| Posicao | Descricao |
| --- | --- | --- |
| Tipo de 'ataque'| 1 | Define qual dos metodos de 'ataque' vai ser utilizado|
| Porta de inicio | 2 | Define por qual porta do destino vai comecar o ataque |
| Porta de fim | 3 | Define por qual porta do destino vai acabar o ataque|

#### Tipos de ataque:
Abaixo temos uma lista com os metodos disponiveis para uso, com os respectivos codigos

| Metodo| Codigo | Descricao |
| --- | --- | --- |
| TCP connect| 1 | Envia mensagem de SYN para uma porta, se a porta estiver aberta recebe um SYN/ACK de volta e por fim manda um ACK, dando fim ao handshaking|
| TCP half-opening | 2 | Envia mensagem de SYN para uma porta, se a porta estiver aberta recebe um SYN/ACK de volta e por fim manda um pacote RST para fechar a conexao|
| TCP FIN | 3 | Uma mensagem FIN e enviada para uma porta, se a porta estiver fechada um RST deve ser recebido, senao a porta esta aberta|
| SYN/ACK | 4 | Uma mensagem SYN/ACK e enviada para uma porta, se a porta estiver aberta, um RST deve ser recebido, senao a porta esta fechada|
 


#### Exemplo:
Exemplo de execucao utilizando o metodo **tcp connect** e o range de portas definidos entre 80 e 120
    
    
    sudo python send_functions.py 1 80 120
