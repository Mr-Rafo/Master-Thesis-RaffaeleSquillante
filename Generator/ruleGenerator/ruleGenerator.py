#!/usr/bin/env python3
import getpass
import re
import sys
import math
import json
import random

import paramiko
from bitstring import BitArray
from ipaddress import ip_network, ip_address
from socket import inet_aton
import itertools
import paramiko


def convertIpAddressesIntoCdirMaxRules(ipAddresses, maxRuleAmount):
    currentPrefixSize = 32

    binaryIpAddresses = [BitArray(inet_aton(ipAddress)).bin for ipAddress in ipAddresses]
    binaryIpAddresses.sort()

    prefixIdCounter = activePrefixIds = len(binaryIpAddresses)
    prefixIdMemory = [[32, i] for i in range(1, prefixIdCounter + 1)]

    def updatePrefixIdMemoryRange(startIndex, endIndex, newPrefixSize):
        nonlocal prefixIdCounter, activePrefixIds, prefixIdMemory
        prefixIdsToRemove = len(set([memoryValue[1] for memoryValue in prefixIdMemory[startIndex:endIndex + 1]])) - 1

        if prefixIdsToRemove > 0:
            # print(prefixIdsToRemove, prefixIdMemory, startIndex, endIndex, newPrefixSize)

            prefixIdCounter = prefixIdCounter + 1
            activePrefixIds -= prefixIdsToRemove
            newPrefixIdMemoryValue = [newPrefixSize, prefixIdCounter]

            endIndex += 1
            prefixIdMemory[startIndex:endIndex] = itertools.repeat(newPrefixIdMemoryValue, (endIndex - startIndex))

    while activePrefixIds > maxRuleAmount:
        currentPrefixSize = currentPrefixSize - 1

        # Make a list scoped to the current prefix size
        currentPrefixList = [ipAddress[0:currentPrefixSize] for ipAddress in binaryIpAddresses]

        # Loop through the list with prefixes and check for duplicates
        oldestEqualPrefixListIndex = 0
        oldestEqualPrefixListValue = currentPrefixList[0]

        for currentPrefixListIndex, currentPrefixListValue in enumerate(currentPrefixList):
            # Check if sequence has been broken
            if activePrefixIds <= maxRuleAmount:
                break
            if currentPrefixListValue != oldestEqualPrefixListValue:
                # Check if multiple equal values
                if oldestEqualPrefixListIndex != currentPrefixListIndex - 1:
                    # We have matches, check amount of overlap with prefixIdMemory
                    updatePrefixIdMemoryRange(oldestEqualPrefixListIndex, currentPrefixListIndex - 1, currentPrefixSize)

                # Reset memory
                oldestEqualPrefixListIndex = currentPrefixListIndex
                oldestEqualPrefixListValue = currentPrefixListValue
            elif currentPrefixListIndex == len(currentPrefixList) - 1:
                # Check if multiple equal values
                if oldestEqualPrefixListValue == currentPrefixListValue:
                    # We have matches, check amount of overlap with prefixIdMemory
                    updatePrefixIdMemoryRange(oldestEqualPrefixListIndex, currentPrefixListIndex, currentPrefixSize)

                # Reset memory
                oldestEqualPrefixListIndex = currentPrefixListIndex
                oldestEqualPrefixListValue = currentPrefixListValue

    # Initialize a list with resulting prefixes
    resultList = []
    passedMemoryEntries = set()
    for memoryIndex, memoryEntry in enumerate(prefixIdMemory):
        if memoryEntry[1] not in passedMemoryEntries:
            passedMemoryEntries.add(memoryEntry[1])

            # Get the prefix size for the current prefix
            prefixSize = memoryEntry[0]
            slicedBinaryIpAddress = binaryIpAddresses[memoryIndex][0:prefixSize]

            # Pad the IP address with zeroes again and convert it into a decimal representation
            decimalIpAddress = str(ip_address(int(slicedBinaryIpAddress.ljust(32, '0'), 2)))

            # Add the prefix to the result list
            resultList.append('{}/{}'.format(decimalIpAddress, prefixSize))

    return resultList


# Generate Type 2 rule component
def getSourceIps(fingerprintSourceIps):
    ip_set = []
    for ip in fingerprintSourceIps:
        if isinstance(ip, dict):
            ip_set.append(ip['ip'])
        else:
            ip_set.append(ip)
    return ip_set


# Generate Type 3 rule component
def getIpProtocols(fingerprintProtocol):
    ipProtocols = []

    if fingerprintProtocol in ['TCP']:  # Maybe DNS and Chargen here too!
        ipProtocols.append(6)
    if fingerprintProtocol in ['UDP', 'DNS', 'Chargen', 'QUIC', 'NTP', 'SSDP']:
        ipProtocols.append(17)
    if fingerprintProtocol in ['ICMP']:
        ipProtocols.append(1)

    return ipProtocols


# Generate Type 5 or Type 6 rule component
def getPorts(fingerprintPorts):
    ports = []

    try:
        port_list = fingerprintPorts.split(',')
        for port in port_list:
            port_num = int(port)
            ports.append(str(port_num))  # Convert the port to a string before appending
    except ValueError:
        pass

    return ports


# Generate Type 7 rule component
def getIcmpType(fingerprintIcmpType):
    return int(float(fingerprintIcmpType))


# Generate Type 9 rule component
def getTcpFlag(fingerprintTcpFlag):
    tcpFlags = []
    seen_flags = set()

    fingerprintFilterer = fingerprintTcpFlag.replace('.', '')

    for flag in fingerprintFilterer:
        if flag == 'S' and 'syn' not in seen_flags:
            tcpFlags.append('syn')
            seen_flags.add('syn')
        elif flag == 'E' and 'ecn' not in seen_flags:
            tcpFlags.append('ecn')
            seen_flags.add('ecn')
        elif flag == 'C' and 'cwr' not in seen_flags:
            tcpFlags.append('cwr')
            seen_flags.add('cwr')
        elif flag == 'U' and 'urg' not in seen_flags:
            tcpFlags.append('urg')
            seen_flags.add('urg')
        elif flag == 'A' and 'ack' not in seen_flags:
            tcpFlags.append('ack')
            seen_flags.add('ack')
        elif flag == 'P' and 'psh' not in seen_flags:
            tcpFlags.append('psh')
            seen_flags.add('psh')
        elif flag == 'R' and 'rst' not in seen_flags:
            tcpFlags.append('rst')
            seen_flags.add('rst')
        elif flag == 'F' and 'fin' not in seen_flags:
            tcpFlags.append('fin')
            seen_flags.add('fin')

    return tcpFlags


def wrapMatchStatement(statement):
    return "            " + statement + ";\n"


def parseRuleToJunos2(rule):
    matchBlock = ""
    # Destination
    if 'type1' in rule.keys():
        matchBlock += wrapMatchStatement("destination " + rule['type1'])
    if 'type2' in rule.keys():
        matchBlock += wrapMatchStatement("source " + rule['type2'])
    if 'type3' in rule.keys():
        protocolMap = {
            1: "icmp",
            6: "tcp",
            17: "udp"
        }
        for protocol in rule['type3']:
            matchBlock += wrapMatchStatement("protocol " + protocolMap[protocol])
    if 'type5' in rule.keys():
        matchBlock += wrapMatchStatement("destination-port " + str(rule['type5']))
    if 'type6' in rule.keys():
        matchBlock += wrapMatchStatement("source-port " + str(rule['type6']))
    if 'type7' in rule.keys():
        matchBlock += wrapMatchStatement("icmp-type " + str(rule['type7']))
    # Verifica se ci sono flag TCP prima di aggiungere la riga "match"
    if 'type9' in rule.keys() and rule['type9']:
        # Rimuovi i flag TCP duplicati utilizzando un insieme (set) temporaneo
        tcp_flags_set = set(rule['type9'])
        # Converti l'insieme (set) in una lista di flag TCP unici
        tcp_flags_unique = list(tcp_flags_set)

        # Combina tutti i flag TCP unici nella stessa riga di match, separandoli con uno spazio
        tcp_flags_match = ' '.join(tcp_flags_unique)
        matchBlock += wrapMatchStatement("tcp-flag " + tcp_flags_match)

    return f"""
flow {{
    term-order standard;
    route {random.randint(0, 1000000)} {{
        match {{
{matchBlock}
        }}
        then discard;
    }}
}}
"""


def parseRuleToJunos(rule):
    resultRule = []
    if 'type1' in rule.keys():
        resultRule.append('destination ' + rule['type1'])
    if 'type2' in rule.keys():
        resultRule.append('source ' + rule['type2'])
    if 'type3' in rule.keys():
        protocolMap = {
            1: "icmp",
            6: "tcp",
            17: "udp"
        }
        resultRule.append('protocol ' + protocolMap[rule['type3'][0]])
    if 'type5' in rule.keys():
        resultRule.append('destination-port ' + str(rule['type5']))
    if 'type6' in rule.keys():
        resultRule.append('source-port ' + str(rule['type6']))
    if 'type7' in rule.keys():
        icmpMap = {
            0: "echo-reply",
            3: "unreachable",
            4: "source-quench",
            5: "redirect",
            8: "echo-request",
            9: "router-advertisement",
            10: "router-solicit",
            11: "time-exceeded",
            12: "parameter-problem",
            13: "timestamp",
            14: "timestamp-reply",
            15: "info-request",
            16: "info-reply",
            17: "mask-request",
            18: "mask-reply"
        }
        icmp_type_str = icmpMap.get(rule['type7'])
        if icmp_type_str:
            resultRule.append('icmp-type' + icmp_type_str)

    if 'type9' in rule.keys():
        # Rimuovi i flag TCP duplicati utilizzando un insieme (set) temporaneo
        tcp_flags_set = set(rule['type9'])
        # Converti l'insieme (set) in una lista di flag TCP unici
        tcp_flags_unique = list(tcp_flags_set)

        # Combina tutti i flag TCP unici nella stessa riga di match, separandoli con una virgola
        tcp_flags_str = ','.join(tcp_flags_unique)
        resultRule.append('tcp-flags ' + tcp_flags_str)

    resultRule = "{{" + '} {'.join(resultRule) + "}}"
    return resultRule


def parseRuleToCiscoACL(rule, acl_counter):
    matchBlock = ""
    # Destination
    if 'type1' in rule.keys():
        matchBlock += wrapMatchStatement("destination " + rule['type1'])
    if 'type2' in rule.keys():
        matchBlock += wrapMatchStatement("source " + rule['type2'])
    if 'type3' in rule.keys():
        protocolMap = {
            1: "icmp",
            6: "tcp",
            17: "udp"
        }
        for protocol in rule['type3']:
            matchBlock += wrapMatchStatement("protocol " + protocolMap[protocol])
    if 'type5' in rule.keys():
        matchBlock += wrapMatchStatement("destination-port " + str(rule['type5']))
    if 'type6' in rule.keys():
        matchBlock += wrapMatchStatement("source-port " + str(rule['type6']))
    if 'type7' in rule.keys():
        matchBlock += wrapMatchStatement("icmp-type " + str(rule['type7']))
    # Verifica se ci sono flag TCP prima di aggiungere la riga "match"
    if 'type9' in rule.keys() and rule['type9']:
        # Rimuovi i flag TCP duplicati utilizzando un insieme (set) temporaneo
        tcp_flags_set = set(rule['type9'])
        # Converti l'insieme (set) in una lista di flag TCP unici
        tcp_flags_unique = list(tcp_flags_set)

        # Combina tutti i flag TCP unici nella stessa riga di match, separandoli con uno spazio
        tcp_flags_match = ' '.join(tcp_flags_unique)
        matchBlock += wrapMatchStatement("tcp-flag " + tcp_flags_match)

    # Genera il nome univoco dell'ACL con il contatore incrementale
    acl_name = f"ATTACK_RULE_{acl_counter}"

    return f"""
ip access-list extended {acl_name}
{matchBlock}
deny ip host {rule['type2']} host {rule['type1']} {tcp_flags_match}
"""


def parseRuleToCiscoBGPFlowspec(rule, AS_NUMBER):
    matchBlock = ""
    action = "drop"  # Imposta di default l'azione a "drop"

    # Destination
    if 'type1' in rule.keys():
        matchBlock += wrapMatchStatement("destination-address " + rule['type1'])
    if 'type2' in rule.keys():
        matchBlock += wrapMatchStatement("source-address " + rule['type2'])
    if 'type3' in rule.keys():
        protocolMap = {
            1: "icmp",
            6: "tcp",
            17: "udp"
        }
        for protocol in rule['type3']:
            matchBlock += wrapMatchStatement("transport protocol " + protocolMap[protocol])
    if 'type5' in rule.keys():
        matchBlock += wrapMatchStatement("destination-port " + str(rule['type5']))
    if 'type6' in rule.keys():
        matchBlock += wrapMatchStatement("source-port " + str(rule['type6']))
    if 'type7' in rule.keys():
        matchBlock += wrapMatchStatement("icmp-type " + str(rule['type7']))

    # Verifica se ci sono flag TCP
    if 'type9' in rule.keys() and rule['type9']:
        # Rimuovi i flag TCP duplicati utilizzando un insieme (set) temporaneo
        tcp_flags_set = set(rule['type9'])
        # Converti l'insieme (set) in una lista di flag TCP unici
        tcp_flags_unique = list(tcp_flags_set)

        # Combina tutti i flag TCP unici nella stessa riga di match, separandoli con uno spazio
        tcp_flags_match = ' '.join(tcp_flags_unique)
        matchBlock += wrapMatchStatement("tcp-flag " + tcp_flags_match)

    # Genera il nome univoco dell'ACL con il contatore incrementale
    bgp_flowspec_rule = f"""
router bgp {AS_NUMBER}
 address-family ipv4 flowspec
  match
{matchBlock}
  action {action}
"""
    return bgp_flowspec_rule


def calculate_percentage_limits(fingerprint, rule_limit, total_ips):
    proportional_limits = []

    # Se il numero totale di indirizzi IP è inferiore o uguale al rule_limit,
    # allora assegna il rule_limit direttamente a tutti i vettori di attacco
    if total_ips <= rule_limit:
        return rule_limit

    # Altrimenti, calcola la percentuale proporzionale per ciascun vettore di attacco
    for attack_vector in fingerprint['attack_vectors']:
        percentage_limit = int(len(attack_vector['source_ips']) * rule_limit / total_ips)
        proportional_limits.append(percentage_limit)

    # Normalizza le percentuali in modo che sommino esattamente al rule_limit
    total_proportional_limit = sum(proportional_limits)
    while total_proportional_limit > rule_limit:
        max_limit_index = proportional_limits.index(max(proportional_limits))
        proportional_limits[max_limit_index] -= 1
        total_proportional_limit -= 1

    return proportional_limits


def main():
    fingerprint = None
    destinationIp = '1.1.1.1'
    rule_limit = 6000

    # Read the fingerprint file
    if len(sys.argv) == 2:
        f = open(sys.argv[1], 'r')
        fingerprint = json.loads(f.read())
    else:
        raise ValueError('Please supply a fingerprint file path as an argument')

    # Resulting array
    flowspecRules = []

    # Calcola il numero totale di indirizzi IP in tutti i vettori di attacco
    total_ips = sum(len(attack_vector['source_ips']) for attack_vector in fingerprint['attack_vectors'])

    # Se ci sono più di un vettore di attacco, calcola le percentuali proporzionali
    if len(fingerprint['attack_vectors']) > 1:
        proportional_limits = calculate_percentage_limits(fingerprint, rule_limit, total_ips)
    else:
        # Assegna direttamente rule_limit a tutti i vettori di attacco
        proportional_limits = [rule_limit]

    # Loop through all attack vectors
    for idx, attack_vector in enumerate(fingerprint['attack_vectors']):
        # Ottieni il limite percentuale per il vettore di attacco corrente
        percentage_limit = proportional_limits[idx] if total_ips > rule_limit else rule_limit

        # Rule that will be used as a template for each attack vector
        baseFlowspecRule = {}

        # Collect Type 1 (Destination IP)
        baseFlowspecRule['type1'] = '{}/32'.format(destinationIp)

        # Type 2 will be dynamically generated and added to the resulting ruleset later
        source_ips = getSourceIps(attack_vector['source_ips'])

        # Collect Type 3 (IP protocol)
        type3 = getIpProtocols(attack_vector['protocol'])
        baseFlowspecRule['type3'] = type3

        # Collect Type 5 (Destination ports)
        if 'destination_ports' in attack_vector:
            type5_ports = attack_vector['destination_ports']
            if isinstance(type5_ports, dict):  # Case when 'destination_ports' is a dictionary like {"21": 1.0}
                type5_ports_list = list(type5_ports.keys())
            else:  # Case when 'destination_ports' is a single integer like 21
                type5_ports_list = [str(type5_ports)]
            if len(type5_ports_list) == 1:
                if type5_ports_list[0] != "0":  # Check if the destination port is not 0 before processing
                    type5 = getPorts(type5_ports_list[0])  # Pass the single port value as a string
                    if type5:  # Check if type5 is not empty before assigning the value
                        baseFlowspecRule['type5'] = type5[0]

        # Collect Type 6 (Source ports)
        if 'source_port' in attack_vector:
            type6_ports = attack_vector['source_port']
            if isinstance(type6_ports, dict):  # Case when 'source_port' is a dictionary like {"21": 1.0}
                type6_ports_list = list(type6_ports.keys())
            else:  # Case when 'source_port' is a single integer like 21
                type6_ports_list = [str(type6_ports)]
            if len(type6_ports_list) == 1:  # Split the ports by comma and check the number of individual ports
                if type6_ports_list[0] != "0":  # Check if the destination port is not 0 before processing
                    type6 = getPorts(type6_ports_list[0])  # Pass the single port value as a string
                    if type6:  # Check if type6 is not empty before assigning the value
                        baseFlowspecRule['type6'] = type6[0]

        # If ICMP, collect its ICMP information
        if 1 in type3:
            # Collect type 7
            baseFlowspecRule['type7'] = getIcmpType(attack_vector['icmp_type']['Echo'])

        # If TCP, collect its flag information
        if 6 in type3:
            # Collect type 9
            tcp_flags_object = attack_vector['tcp_flags']
            tcp_flags_string = ''.join(tcp_flags_object.keys())
            baseFlowspecRule['type9'] = getTcpFlag(tcp_flags_string)

        source_ips = convertIpAddressesIntoCdirMaxRules(source_ips, percentage_limit)

        for ip in source_ips:
            tempRule = baseFlowspecRule.copy()
            tempRule['type2'] = ip
            flowspecRules.append(tempRule)

    return flowspecRules


def ipValid(ip):
    # Pattern per un indirizzo IPv4
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

    # Verifica se l'indirizzo IP corrisponde al pattern
    if re.match(ip_pattern, ip):
        return True
    else:
        return False


if __name__ == '__main__':
    ruleset = main()

    opzione_valida = False
    acl_counter = 1
    ip_ssh = input("Inserisci Indirizzo IP Router:")
    while not ipValid(ip_ssh):
        ip_ssh = input("IP Non Conforme, Inserisci Indirizzo IP Router:")
    user_ssh = input("Inserisci User Router:")
    pw_ssh = getpass.getpass("Inserisci PW Router:")

    while not opzione_valida:
        print("Scegli un'opzione:")
        print("1. Regole formato standard")
        print("2. Regole formato Juniper")
        print("3. Regole formato Cisco")
        print("4. Regole formato ACL")
        print("5. Regole formato personalizzato")
        print("6. Modifica Parametri SSH")
        print("0. Esci")

        scelta = input("Inserisci il numero dell'opzione desiderata: ")

        if scelta == '0':
            print("Arrivederci!")
            break
        elif scelta not in ('1', '2', '3', '4', '5', '6'):
            print("Opzione non valida. Riprova.")
        else:
            opzione_valida = True
            result = []
            ssh = []
            if scelta == '1':
                for rule in ruleset:
                    result.append(rule)
            elif scelta == '2':
                i = 0
                groupname = input("Inserisci il Group Name della rete BGP: ")
                peerip = input("Inserisci un IP di un Peer BGP: ")
                while not ipValid(peerip):
                    peerip = input("IP Non Conforme, Inserisci Indirizzo IP di un Peer BGP:")
                for rule in ruleset:
                    result.append(parseRuleToJunos2(rule))
                    regola = str(parseRuleToJunos2(rule))
                    regola = regola.replace('\n', ' ')
                    pattern = r'match(.*?)\}'
                    match_result = re.search(pattern, regola)
                    if match_result:
                        ssh.append("edit protocols bgp")
                        ssh.append("set group " + groupname + " family flowspec unicast")
                        ssh.append("edit policy-options policy-statement " + str(i))
                        ssh.append("set term " + str(i) + " from match" + match_result.group(1)+"}")
                        ssh.append("set term " + str(i) + " then discard")
                        stringa1 = "set group " + groupname + " neighbor " + peerip
                        stringa2 = " family flowspec unicast route-policy " + str(i) + " term " + str(i)
                        ssh.append(stringa1+stringa2)
                        ssh.append("commit")
                    i = i + 1
            elif scelta == '3':
                AS_NUMBER = input("Inserisci l'AS_NUMBER del tuo sistema: ")
                peerip = input("Inserisci un IP di un Peer BGP: ")
                while not ipValid(peerip):
                    peerip = input("IP Non Conforme, Inserisci Indirizzo IP di un Peer BGP:")
                for rule in ruleset:
                    result.append(parseRuleToCiscoBGPFlowspec(rule, AS_NUMBER))
                    regola = str(parseRuleToCiscoBGPFlowspec(rule,AS_NUMBER))
                    parti = regola.split('\n')
                    pattern = r'match(.*?)action'
                    regola = regola.replace('\n',' ')
                    match_result = re.search(pattern, regola)
                    ssh.append("configure terminal")
                    ssh.append(parti[1])
                    ssh.append(parti[2])
                    ssh.append(parti[3] + " " + match_result.group(1))
                    ssh.append(parti[9])
                    ssh.append("exit")
                    ssh.append("neighbor " + peerip)
            elif scelta == '4':
                for rule in ruleset:
                    result.append(parseRuleToCiscoACL(rule, acl_counter))
                    acl_counter += 1
            elif scelta == '5':
                for rule in ruleset:
                    result.append(parseRuleToJunos(rule))
            elif scelta == '6':
                ip_ssh = input("Inserisci Indirizzo IP Router:")
                while not ipValid(ip_ssh):
                    ip_ssh = input("IP Non Conforme, Inserisci Indirizzo IP Router:")
                user_ssh = input("Inserisci User Router:")
                pw_ssh = getpass.getpass("Inserisci PW Router:")

            with open("ruleset.txt", "w") as output_file:
                for rule in result:
                    print(rule, file=output_file)
            with open("ssh.txt", "w") as output_file:
                """
                # Crea Oggetto Client SSH
                sshclient = paramiko.SSHClient()

                # Ignora Errori SSH (per fini di sviluppo)
                sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    # Connessione SSH
                    sshclient.connect(ip_ssh, port=22, username=user_ssh, password=pw_ssh)
                    for command in ssh:
                        # Viene eseguito ogni comando, ovvero viene inserita ogni regola BGP Flowspec
                        stdin, stdout, stderr = sshclient.exec_command(command)
                        output = stdout.read().decode()
                        # Log su STDOUT per Testing
                        print(output)
                        # Log su File TXT
                        print(output + "\n", file=outputfile)
                # Errore di Autenticazione - Credenziali Errate
                except paramiko.AuthenticationException:
                    print("Autenticazione Fallita")
                # Errore Generico di SSH - Ritorna Stacktrace
                except paramiko.SSHException as e:
                    print("Errore SSH", str(e))
                # Finite tutte le operazione, libera la connessione
                finally:
                    sshclient.close()
                """
                # Inserito per fini di sviluppo, da commentare se si abilita il Log SSH
                for command in ssh:
                    print(command, file=output_file)

            print("Le regole sono state generate ed aggiunte al file ruleset.txt")
            print("Il Log dei Comandi SSH Deployati è al file ssh.txt")
