CONSTRUIRE download0.dat (UFS2) VIA GITHUB ACTIONS

Important : le ZIP contient des sources modifiées et un workflow de génération. L'image générée n'a pas été construite ni testée ici. Conservez une copie de votre download0.dat d'origine.

1. Créez un dépôt GitHub vide (par exemple Y2JB-autoload-test).
2. Décompressez ce ZIP sur votre ordinateur.
3. Envoyez le CONTENU du dossier Y2JB-autoload-modified à la racine du dépôt GitHub. Le dossier .github/workflows/build.yml doit être présent dans le dépôt.
4. Dans GitHub, ouvrez l'onglet Actions. Si demandé, autorisez les actions pour ce dépôt.
5. Choisissez « Build Y2JB download0.dat (UFS2) » dans la colonne de gauche.
6. Cliquez « Run workflow », sélectionnez la branche main, puis « Run workflow ».
7. Attendez que le workflow devienne vert. Ouvrez l'exécution terminée et téléchargez l'artefact « download0-dat-ufs2 ».
8. Décompressez cet artefact : il doit contenir download0.dat.

Ne remplacez pas encore l'image sur la PS5 : cette compilation automatique ne prouve pas que le lancement Payload Manager fonctionne. Le patch est expérimental et doit être vérifié avant utilisation.

Si l'onglet Actions signale une erreur, ouvrez l'exécution et copiez le message d'erreur complet pour le diagnostic.
