#!/usr/bin/env python3

import os
import sys
import time
from pathlib import Path
import shutil

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    width = get_terminal_width()
    
    clear_screen()
    print(f"\n{Colors.CYAN}{'═' * width}")
    print(f"║{' ' * (width-2)}║")
    
    # Titre principal XDECOMPILER en gros
    title = "XDECOMPILER"
    padding = (width - len(title) - 2) // 2
    print(f"║{' ' * padding}{Colors.BOLD}{Colors.YELLOW}{title}{Colors.ENDC}{Colors.CYAN}{' ' * padding}║")
    
    print(f"║{' ' * (width-2)}║")
    
    subtitle = "Extraction et décompilation maximale multilangage"
    padding = (width - len(subtitle) - 2) // 2
    print(f"║{' ' * padding}{Colors.WHITE}{subtitle}{Colors.CYAN}{' ' * padding}║")
    
    print(f"║{' ' * (width-2)}║")
    print(f"{'═' * width}{Colors.ENDC}")
    print()

def show_menu():
    print(f"{Colors.BOLD}{Colors.CYAN}MENU PRINCIPAL:{Colors.ENDC}")
    print(f"{Colors.GREEN}1.{Colors.ENDC} Décompiler un fichier")
    print(f"{Colors.GREEN}2.{Colors.ENDC} Afficher les langages supportés")
    print(f"{Colors.GREEN}3.{Colors.ENDC} Installer les dépendances")
    print(f"{Colors.GREEN}4.{Colors.ENDC} Exécuter les tests")
    print(f"{Colors.GREEN}5.{Colors.ENDC} Quitter")
    print()

def show_supported_languages():
    print(f"{Colors.BOLD}{Colors.CYAN}LANGAGES SUPPORTÉS:{Colors.ENDC}")
    
    languages = [
        ("Python", ".pyc → .py", Colors.GREEN),
        ("JavaScript", ".js", Colors.YELLOW),
        (".NET/C#", ".dll → .cs", Colors.BLUE),
        ("Java", ".jar → .java", Colors.RED),
        ("C++", "patterns", Colors.PURPLE),
        ("AutoHotkey", ".ahk", Colors.CYAN),
        ("Electron", "asar → .js", Colors.MAGENTA),
        ("Ressources", "PE, fichiers", Colors.WHITE)
    ]
    
    for lang, ext, color in languages:
        print(f"  {color}{lang:<12}{Colors.ENDC} {ext}")
    print()

def select_file():
    print(f"{Colors.BOLD}{Colors.CYAN}SÉLECTION DU FICHIER:{Colors.ENDC}")
    
    print(f"{Colors.GREEN}1.{Colors.ENDC} Glisser-déposer le fichier")
    print(f"{Colors.GREEN}2.{Colors.ENDC} Saisir le chemin manuellement")
    print(f"{Colors.GREEN}3.{Colors.ENDC} Retour au menu")
    
    choice = input(f"\n{Colors.YELLOW}Votre choix (1-3): {Colors.ENDC}")
    
    if choice == '1':
        file_path = input(f"{Colors.CYAN}Glissez le fichier ici et appuyez sur Entrée: {Colors.ENDC}").strip().strip('"')
    elif choice == '2':
        file_path = input(f"{Colors.CYAN}Chemin complet du fichier: {Colors.ENDC}").strip()
    elif choice == '3':
        return None
    else:
        print(f"{Colors.RED}Choix invalide.{Colors.ENDC}")
        return None
    
    if not os.path.exists(file_path):
        print(f"{Colors.RED}Fichier non trouvé: {file_path}{Colors.ENDC}")
        return None
    
    return file_path

def decompile_file(file_path):
    print(f"{Colors.BOLD}{Colors.CYAN}DÉCOMPILATION EN COURS:{Colors.ENDC}")
    print(f"Fichier: {Colors.YELLOW}{file_path}{Colors.ENDC}")
    decompiler_path = os.path.join(os.path.dirname(__file__), 'xdecompiler_enhanced.py')
    if not os.path.exists(decompiler_path):
        print(f"{Colors.RED}Erreur: xdecompiler_enhanced.py non trouvé{Colors.ENDC}")
        return
    
    print(f"{Colors.CYAN}Lancement de la décompilation...{Colors.ENDC}")
    
    try:
        import subprocess
        result = subprocess.run([
            sys.executable, decompiler_path, file_path
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}Décompilation terminée avec succès{Colors.ENDC}")
            print(f"Sortie: {result.stdout}")
        else:
            print(f"{Colors.RED}Erreur lors de la décompilation{Colors.ENDC}")
            print(f"Erreur: {result.stderr}")
    except Exception as e:
        print(f"{Colors.RED}Erreur: {str(e)}{Colors.ENDC}")

def install_dependencies():
    print(f"{Colors.BOLD}{Colors.CYAN}INSTALLATION DES DÉPENDANCES:{Colors.ENDC}")
    
    installer_path = os.path.join(os.path.dirname(__file__), 'install_ultimate_dependencies.py')
    if not os.path.exists(installer_path):
        print(f"{Colors.RED}Erreur: install_ultimate_dependencies.py non trouvé{Colors.ENDC}")
        return
    
    try:
        import subprocess
        result = subprocess.run([sys.executable, installer_path], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}Installation terminée avec succès{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Erreur lors de l'installation{Colors.ENDC}")
            print(f"Erreur: {result.stderr}")
    except Exception as e:
        print(f"{Colors.RED}Erreur: {str(e)}{Colors.ENDC}")

def run_tests():
    print(f"{Colors.BOLD}{Colors.CYAN}EXÉCUTION DES TESTS:{Colors.ENDC}")
    
    test_path = os.path.join(os.path.dirname(__file__), 'test_complete.py')
    if not os.path.exists(test_path):
        print(f"{Colors.RED}Erreur: test_complete.py non trouvé{Colors.ENDC}")
        return
    
    try:
        import subprocess
        result = subprocess.run([sys.executable, test_path], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}Tests terminés avec succès{Colors.ENDC}")
            print(f"Résultat: {result.stdout}")
        else:
            print(f"{Colors.RED}Erreur lors des tests{Colors.ENDC}")
            print(f"Erreur: {result.stderr}")
    except Exception as e:
        print(f"{Colors.RED}Erreur: {str(e)}{Colors.ENDC}")

def main():
    if os.name == 'nt':
        os.system('')
    
    while True:
        banner()
        show_menu()
        
        choice = input(f"{Colors.YELLOW}Votre choix (1-5): {Colors.ENDC}")
        
        if choice == '1':
            file_path = select_file()
            if file_path:
                decompile_file(file_path)
                input(f"\n{Colors.CYAN}Appuyez sur Entrée pour continuer...{Colors.ENDC}")
        
        elif choice == '2':
            show_supported_languages()
            input(f"\n{Colors.CYAN}Appuyez sur Entrée pour continuer...{Colors.ENDC}")
        
        elif choice == '3':
            install_dependencies()
            input(f"\n{Colors.CYAN}Appuyez sur Entrée pour continuer...{Colors.ENDC}")
        
        elif choice == '4':
            run_tests()
            input(f"\n{Colors.CYAN}Appuyez sur Entrée pour continuer...{Colors.ENDC}")
        
        elif choice == '5':
            print(f"{Colors.GREEN}Au revoir!{Colors.ENDC}")
            break
        
        else:
            print(f"{Colors.RED}Choix invalide. Veuillez choisir entre 1 et 5.{Colors.ENDC}")
            time.sleep(1)

if __name__ == "__main__":
    main()
