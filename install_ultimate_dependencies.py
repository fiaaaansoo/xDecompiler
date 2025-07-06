#!/usr/bin/env python3

import subprocess
import sys
import os
import platform
from pathlib import Path

def run_command(cmd, description=""):
    print(f"\n{description}")
    print(f"Commande: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"Succès: {description}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Échec: {description}")
        print(f"Erreur: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"Commande non trouvée: {description}")
        return False

def install_python_packages():
    packages = [
        'uncompyle6',
        'decompyle3', 
        'pycdc',
        'pyinstxtractor',
        'python-magic-bin',
        'python-magic',
        'binwalk'
    ]
    
    print("\n=== Installation des packages Python ===")
    
    for package in packages:
        run_command([sys.executable, '-m', 'pip', 'install', package], 
                   f"Installation de {package}")

def install_nodejs_tools():
    print("\n=== Installation des outils Node.js ===")
    
    try:
        subprocess.run(['npm', '--version'], capture_output=True, check=True)
        print("npm est disponible")
    except:
        print("npm n'est pas disponible - certaines fonctionnalités seront limitées")
        return False
    
    run_command(['npm', 'install', '-g', 'asar'], "Installation d'asar")
    run_command(['npm', 'install', '-g', 'js-beautify'], "Installation de js-beautify")
    
    return True

def install_java_tools():
    print("\n=== Installation des outils Java ===")
    
    try:
        result = subprocess.run(['java', '-version'], capture_output=True, text=True)
        print("Java est disponible")
    except:
        print("Java n'est pas disponible - certaines fonctionnalités seront limitées")
        return False
    
    print("\nInstructions pour JADX:")
    print("1. Télécharger JADX depuis: https://github.com/skylot/jadx/releases")
    print("2. Extraire l'archive dans un dossier")
    print("3. Ajouter le dossier bin/ au PATH système")
    print("4. Redémarrer le terminal")
    
    return True

def install_dotnet_tools():
    print("\n=== Installation des outils .NET ===")
    
    try:
        result = subprocess.run(['dotnet', '--version'], capture_output=True, text=True)
        print(".NET est disponible")
    except:
        print(".NET n'est pas disponible - certaines fonctionnalités seront limitées")
        return False
    
    print("\nInstructions pour ILSpy:")
    print("1. Installer .NET SDK depuis: https://dotnet.microsoft.com/download")
    print("2. Installer ILSpy CLI: dotnet tool install --global ilspycmd")
    
    run_command(['dotnet', 'tool', 'install', '--global', 'ilspycmd'], 
               "Installation d'ILSpy CLI")
    
    return True

def install_binary_tools():
    print("\n=== Installation des outils binaires ===")
    
    if platform.system() == "Windows":
        print("Pour Windows, télécharger manuellement:")
        print("1. Binwalk: https://github.com/ReFirmLabs/binwalk")
        print("2. 7-Zip: https://www.7-zip.org/")
        print("3. WinRAR ou alternative")
        
        run_command([sys.executable, '-m', 'pip', 'install', 'binwalk'], 
                   "Installation de binwalk via pip")
                   
    else:
        print("Pour Linux/macOS:")
        print("sudo apt-get install binwalk (Ubuntu/Debian)")
        print("brew install binwalk (macOS)")

def create_test_script():
    test_script = '''#!/usr/bin/env python3

import sys
import os
from pathlib import Path

def test_ultimate_extractor():
    print("Test de xDecompiler Ultimate")
    
    if os.name == 'nt':
        test_file = Path("C:/Windows/System32/calc.exe")
        if test_file.exists():
            print(f"Test avec: {test_file}")
            
            try:
                from xdecompiler_ultimate import UltimateExtractor
                
                extractor = UltimateExtractor(str(test_file))
                success = extractor.extract_all()
                
                if success:
                    print("Test réussi!")
                    print(f"Résultats dans: {extractor.output_dir}")
                else:
                    print("Test échoué")
                    
            except Exception as e:
                print(f"Erreur de test: {e}")
        else:
            print("calc.exe non trouvé")
    else:
        print("Test automatique disponible seulement sur Windows")

if __name__ == "__main__":
    test_ultimate_extractor()
'''
    
    with open("test_ultimate.py", "w", encoding="utf-8") as f:
        f.write(test_script)
    
    print("Script de test créé: test_ultimate.py")

def main():
    print("Installation des dépendances pour xDecompiler Ultimate")
    print("=" * 60)
    
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 7):
        print("Python 3.7+ requis")
        sys.exit(1)
    
    install_python_packages()
    install_nodejs_tools()
    install_java_tools()
    install_dotnet_tools()
    install_binary_tools()
    
    create_test_script()
    
    print("\n" + "=" * 60)
    print("Installation terminée!")
    print("\nProchaines étapes:")
    print("1. Redémarrer le terminal")
    print("2. Tester avec: python test_ultimate.py")
    print("3. Utiliser avec: python xdecompiler_ultimate.py <fichier.exe>")
    
    print("\nFonctionnalités disponibles:")
    print("• Extraction Python (PyInstaller, py2exe, etc.)")
    print("• Décompilation .pyc → .py (uncompyle6, decompyle3)")
    print("• Extraction Electron (.asar → .js)")
    print("• Décompilation .NET (.exe → .cs)")
    print("• Décompilation Java (.jar → .java)")
    print("• Extraction de patterns de code source")
    print("• Rapport d'extraction détaillé")

if __name__ == "__main__":
    main()
