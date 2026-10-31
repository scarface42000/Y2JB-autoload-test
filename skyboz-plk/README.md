# SKYBOZ LOADER — base PLK 1.1.0

Version personnalisée de [itsPLK/ps5-y2jb-autoloader](https://github.com/itsPLK/ps5-y2jb-autoloader), figée au commit `ba879c8609f0d9e8208fd9a64ca678ed47bd4291` (v1.1.0).

La tuile provient de `assets/icon0-PPSA01650.png` du dépôt SKYBOZ. L'écran de chargement reprend cette image en fond discret et utilise un thème rouge et noir. Il s'agit du fond **dans l'application**, pas du fond du menu système PS5. Le texte de la tuile système reste celui de YouTube : cette version ne modifie ni `app.db`, ni `appinfo.db`, ni les fichiers `param.json`.

Le runtime PLK, ses contrôles de progression, son updater et son autoloader unifié sont conservés. Les versions des trois binaires sont figées et leurs SHA-256 vérifiés dans `build.py`. Les sources antérieures dans `payloads/` restent disponibles comme historique mais ne sont pas utilisées par ce build.

## Installer

Dans GitHub **Actions → Build SKYBOZ PLK → dernier build réussi → Artifacts**, télécharger `skyboz-plk-ready-files` et décompresser cette archive d'artefacts sur le PC.

- **Première installation ou migration depuis l'ancien SKYBOZ :** fermer YouTube, conserver une copie de l'ancien `download0.dat`, puis remplacer `/user/download/PPSA01650/download0.dat` par le nouveau `download0.dat` via FTP. Adapter l'identifiant si l'application est PPSA01651 ou PPSA01652. L'ancien SKYBOZ n'intègre pas l'updater PLK : le ZIP USB seul ne suffit pas pour cette migration.
- **Mises à jour suivantes, ou installation PLK déjà équipée de cet updater :** placer `y2jb_update.zip` **sans le décompresser** à la racine de la clé USB et lancer YouTube. Le programme vérifie et installe la mise à jour ; le ZIP est normalement supprimé après réussite. Retirer la clé après la fin de l'opération. Relancer YouTube pour utiliser les nouveaux scripts.
- L'installation ne restaure pas les noms de tuile ou les bases de données précédemment modifiés par l'ancien helper. Ne pas restaurer une ancienne base de données complète pour simplement changer le nom de la tuile.

Pour le firmware 13.60, PLK indique YouTube `v01.009.253`. Une connexion au réseau local est nécessaire ; Internet n'est pas requis sur la console.

## Payloads

La configuration USB est prioritaire sur `/data/ps5_autoloader/autoload.txt`. Les dossiers spécifiques `ps5_autoloader_PPSA01650` (ou autre TITLE_ID) sont prioritaires sur le dossier générique.

Sans configuration `autoload.txt`, PLK lance Payload Manager. Si une configuration existe, elle définit la chaîne : pour aussi lancer Payload Manager, placer son fichier `pldmgr.elf` dans le dossier et ajouter son nom à `autoload.txt`. Le programme ne modifie pas automatiquement les configurations ou payloads déjà présents.

## Personnaliser et construire

- Tuile : remplacer `src/icon0.png` par un PNG de 512×512 pixels.
- Fond et couleurs du loader : modifier `src/skyboz.css`. Le fond actuel utilise la même image que la tuile ; ajouter une image distincte dans `src/` puis modifier son URL dans le CSS si souhaité.
- Titre affiché dans le loader : `src/main.js`.
- Construire sous Linux/macOS : `python3 skyboz-plk/build.py --version skyboz-1.1.0`, puis `python3 skyboz-plk/verify_package.py skyboz-plk/dist/y2jb_update.zip`. Nécessite Python 3, curl et Node.js pour la vérification. GitHub Actions fabrique également l'image UFS2 `download0.dat` sous FreeBSD.

## Provenance et licences

Travail original Y2JB par Gezine et contributeurs ; autoloader et updater par PLK et contributeurs. Sources amont et crédits complets : [README PLK](https://github.com/itsPLK/ps5-y2jb-autoloader/blob/ba879c8609f0d9e8208fd9a64ca678ed47bd4291/README.md).

Les ajouts PLK et cette adaptation sont distribués sous **GPL-3.0** (`LICENSE`). Le code de base Y2JB conserve sa licence MIT (`LICENSE-MIT`) et ses notices. Les licences des binaires restent celles des projets [elfldr](https://github.com/itsPLK/ps5-elfldr), [kexp](https://github.com/itsPLK/ps5-kexp) et [unified-autoloader](https://github.com/itsPLK/ps5-unified-autoloader).

La validation automatisée contrôle la construction et le contenu des paquets. Un essai réel sur PS5 reste nécessaire pour valider l'affichage Cobalt, l'actualisation de la tuile et le chargement des payloads.
