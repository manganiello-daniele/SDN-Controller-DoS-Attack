#!/usr/bin/env python3
import json
import os
import re

# Percorso del file JSON
JSON_FILE = "admin_lists.json"

# Regex per validare il formato MAC address
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

def load_data():
    """Carica o crea il file JSON se non esiste."""
    if not os.path.exists(JSON_FILE):
        data = {"blacklist": [], "whitelist": []}
        save_data(data)
    with open(JSON_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    """Salva i dati nel file JSON."""
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=4)

def is_valid_mac(mac):
    """Verifica che il MAC address sia valido."""
    return bool(MAC_REGEX.match(mac))

def add_mac(data, mac, list_name):
    """Aggiunge un MAC alla lista specificata."""
    other_list = "whitelist" if list_name == "blacklist" else "blacklist"

    if mac in data[list_name]:
        print(f" {mac} è già presente nella {list_name}.")
        return
    if mac in data[other_list]:
        print(f"  {mac} è già presente nella {other_list}, impossibile aggiungerlo.")
        return

    data[list_name].append(mac)
    save_data(data)
    print(f" {mac} aggiunto con successo alla {list_name}.")

def show_lists(data):
    """Mostra le liste correnti."""
    print("\n Liste correnti:")
    print("Blacklist:", ", ".join(data["blacklist"]) or "vuota")
    print("Whitelist:", ", ".join(data["whitelist"]) or "vuota")
    print()

def main():
    data = load_data()

    while True:
        print("\n--- Gestione MAC Address ---")
        print("1. Aggiungi MAC alla blacklist")
        print("2. Aggiungi MAC alla whitelist")
        print("3. Mostra liste correnti")
        print("4. Esci")

        choice = input("\nSeleziona un'opzione: ").strip()

        if choice == "1" or choice == "2":
            mac = input("Inserisci il MAC address (formato XX:XX:XX:XX:XX:XX): ").strip()
            if not is_valid_mac(mac):
                print(" Formato MAC non valido.")
                continue

            target_list = "blacklist" if choice == "1" else "whitelist"
            add_mac(data, mac, target_list)

        elif choice == "3":
            show_lists(data)

        elif choice == "4":
            print(" Uscita dal programma.")
            break

        else:
            print(" Scelta non valida. Riprova.")

if __name__ == "__main__":
    main()

