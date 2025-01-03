[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_jsjaws-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-jsjaws)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-jsjaws)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-jsjaws)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-jsjaws)](./LICENSE)

# Jsjaws Service

This service provides sandboxing for JavaScript execution.

## Service Details

This Assemblyline service integrates components from six open-source projects:

- [Malware Jail](https://github.com/HynekPetrak/malware-jail), which provides a sandbox for semi-automatic Javascript
  malware analysis, deobfuscation and payload extraction.
- [Box.js](https://github.com/CapacitorSet/box-js), which is a sandbox tool for studying JavaScript malware.
- [JS-X-Ray](https://github.com/NodeSecure/js-x-ray), which is a tool for static analysis via SAST scanning.
- [Synchrony](https://github.com/relative/synchrony), which is a tool for deobfuscating JavaScript that has been obfuscated with obfuscator.io (https://obfuscator.io).
- [WScript Emulator](https://github.com/mrpapercut/wscript), which is a tool for emulating/tracing the Windows Script Host functionality. The libraries that this tool uses have been integrated into the MalwareJail environment.
- [GootLoaderAutoJsDecode](https://github.com/mandiant/gootloader), which contains `GootLoaderAutoJsDecode.js` - a tool used for automatically decoding Gootloader files using static analysis.

Both sandboxes use [Node VM](https://nodejs.org/api/vm.html) under the hood for malware sandboxing, although Box.js prefers a
modified version of Node VM called [vm2](https://github.com/patriksimek/vm2).

### Signatures

JsJaws also uses signatures for the majority of its scoring. These can be run on both the file contents and the sandbox
outputs.

In the `signatures` folder are a bunch of signatures that will affect the scoring of samples. If you have a sample that
needs better detection from this service, and you see output from the MalwareJail or Box.js tool that could
have a signature written for it, then please make a Pull Request or share the sample! Let's improve this!

### Service Parameters

- `allow_download_from_internet` - [default: false]: See "Features included with Internet connectivity" section.
- `max_payloads_extracted` - [default: 50]: Maximum payload files extracted if deep scan is turned off.
- `raise_malware_jail_exc` - [default: false]: Raise a noisy exception if the MalwareJail tool errors, rather than silently letting the other tools output.
- `total_stdout_limit` - [default: 10000]: The limit to number of stdout lines analyzed that werre captured from tools.
- `send_tool_stderr_to_pipe` - [default: false]: If you don't want a tool's STDERR clogging up your terminal, set to true
- `max_gauntlet_runs` - [default: 30]: The maximum number of times that the gauntlet should be run. This usually gets exceeded when a script writes randomly generated content to the DOM.

### Submission Parameters

#### Generic parameters

- `tool_timeout`: The length of time we will allow both Malware Jail and Box.js to individually run for.
- `add_supplementary`: If you want supplementary files to be added to the result, select this.
- `static_signatures`: If you want the signatures to be run against the file contents as well rather than just the
  dynamic excecution output.
- `display_sig_marks`: If you want the lines of code that caused the signatures to be raised to be displayed in the
  ResultSections.
- `static_analysis_only`: If you do not want the file to be executed via Box.js and MalwareJail, and only with static analysis tools such as JS-X-Ray and Synchony, set this to "true".
- `ignore_stdout_limit`: The service-level config `total_stdout_limit` will be ignored if you set this flag to "true".

#### Box.js parameters

- `no_shell_error`: For Box.js, select this flag if you want to.

#### MalwareJail parameters

- `browser`: Browser type for detonation.
- `wscript_only`: By default, detonation takes place within a sandboxed browser. This option allows for the sample to
  be run in WScript only.
- `throw_http_exc`: By selecting the throw_http_exc flag, the sandbox will throw an error in every network call. This
  is useful for attempting different code execution paths.
- `download_payload`: If the service should allow the sample to download any payload from the Internet.
- `extract_function_calls`: Files that each represent a Function Call can be noisy and not particularly useful. This
  flag turns on this extraction.
- `extract_eval_calls`: Files that each represent a Eval Call can be noisy and not particularly useful. This flag turns
  on this extraction.
- `log_errors`: Setting this parameter to true will insert a log of the exception into exception-catching clauses within a script. This is useful for debugging.
- `override_eval`: Setting this parameter to true will use indirect links to `eval` calls. This is key when scoped variables are used. See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval for more information. Use wisely.
- `file_always_exists`: This parameter when set to true will cause the `Scripting.FileSystemObject.FileExists` method to return true.

#### Synchrony parameters

- `enable_synchrony`: Synchrony will most likely extract a "cleaned" file given any JavaScript file, which adds load
  to Assemblyline. So only enable this option if you are sure you want this.

### Features included with Internet connectivity

#### jQuery Fetching

There have been samples that embed malicious code within standard jQuery libraries. If the service Docker container has
access to the Internet, then we can fetch the actual jQuery library and compare the two files, determining the
difference between them and then extracting the difference (aka malicious code). If the service Docker container
does not have Internet access, then please set the `docker_config` value of `allow_internet_access` to `False` in the
`service_manifest.yml`.

### Assemblyline System Safelist

#### JsJaws-specific safelisted items

The file at `al_config/system_safelist.yaml` contains suggested safelisted values that can be added to the Assemblyline system safelist
either by copy-and-pasting directly to the text editor on the page `https://<Assemblyline Instance>/admin/tag_safelist` or through the [Assemblyline Client](https://github.com/CybercentreCanada/assemblyline_client).

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Jsjaws \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-jsjaws

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Jsjaws

Ce service fournit un bac à sable pour l'exécution de JavaScript.

## Détails du service

Ce service Assemblyline intègre des composants issus de six projets open-source :

- [Malware Jail] (https://github.com/HynekPetrak/malware-jail), qui fournit un bac à sable pour l'analyse semi-automatique de logiciels malveillants, la désobfuscation et l'extraction de charges utiles en Javascript
  semi-automatique, la désobfuscation et l'extraction des charges utiles.
- Box.js](https://github.com/CapacitorSet/box-js), qui est un outil de bac à sable pour l'étude des logiciels malveillants en JavaScript.
- JS-X-Ray](https://github.com/NodeSecure/js-x-ray), un outil d'analyse statique par balayage SAST.
- Synchrony](https://github.com/relative/synchrony), qui est un outil de désobfuscation de JavaScript qui a été obfusqué avec obfuscator.io (https://obfuscator.io).
- WScript Emulator](https://github.com/mrpapercut/wscript), qui est un outil permettant d'émuler/de suivre la fonctionnalité Windows Script Host. Les bibliothèques utilisées par cet outil ont été intégrées dans l'environnement MalwareJail.
- GootLoaderAutoJsDecode](https://github.com/mandiant/gootloader), qui contient `GootLoaderAutoJsDecode.js` - un outil utilisé pour décoder automatiquement les fichiers Gootloader en utilisant l'analyse statique.

Les deux bacs à sable utilisent [Node VM] (https://nodejs.org/api/vm.html) sous le capot pour le sandboxing des logiciels malveillants, bien que Box.js préfère une version modifiée de [Node VM] appelée [Node VM] (https://nodejs.org/api/vm.html).
version modifiée de Node VM appelée [vm2](https://github.com/patriksimek/vm2).

### Signatures

JsJaws utilise également des signatures pour la majorité de ses évaluations. Celles-ci peuvent être exécutées à la fois sur le contenu du fichier et sur les sorties du bac à sable.
les sorties.

Dans le dossier `signatures` se trouvent un certain nombre de signatures qui affecteront l'évaluation des échantillons. Si vous avez un échantillon qui
a besoin d'une meilleure détection de la part de ce service, et que vous voyez une sortie de l'outil MalwareJail ou Box.js qui pourrait avoir une signature écrite pour lui, alors vous pouvez utiliser le dossier `signatures`.
avoir une signature écrite pour lui, alors faites une Pull Request ou partagez l'échantillon ! Améliorons cela !

### Paramètres de service

- `allow_download_from_internet` - [default : false] : Voir la section "Fonctionnalités incluses avec la connectivité Internet".
- `max_payloads_extracted` - [default : 50] : Nombre maximum de fichiers utiles extraits si l'analyse approfondie est désactivée.
- `raise_malware_jail_exc` - [default : false] : Lève une exception bruyante en cas d'erreur de l'outil MalwareJail, plutôt que de laisser les autres outils sortir silencieusement.
- `total_stdout_limit` - [défaut : 10000] : La limite du nombre de lignes stdout analysées qui ont été capturées par les outils.
- `send_tool_stderr_to_pipe` - [default : false] : Si vous ne voulez pas que le STDERR d'un outil encombre votre terminal, mettez-le à true.
- `max_gauntlet_runs` - [default : 30] : Le nombre maximum de fois que le gauntlet doit être exécuté. Ce nombre est généralement dépassé lorsqu'un script écrit un contenu généré aléatoirement dans le DOM.

### Paramètres de soumission

#### Paramètres génériques

- `tool_timeout` : La durée d'exécution de Malware Jail et de Box.js.
- `add_supplementary` : Si vous souhaitez que des fichiers supplémentaires soient ajoutés au résultat, sélectionnez cette option.
- `static_signatures` : Si vous souhaitez que les signatures soient également exécutées sur le contenu des fichiers plutôt que sur la sortie de l'exécution dynamique.
  sortie de l'exécution dynamique.
- `display_sig_marks` : Si vous voulez que les lignes de code qui ont provoqué la levée des signatures soient affichées dans les
  ResultSections.
- `static_analysis_only` : Si vous ne voulez pas que le fichier soit exécuté via Box.js et MalwareJail, et seulement avec des outils d'analyse statique tels que JS-X-Ray et Synchony, mettez ceci à "true".
- `ignore_stdout_limit` : La configuration au niveau du service `total_stdout_limit` sera ignorée si vous mettez ce drapeau à "true".

#### Paramètres de Box.js

- `no_shell_error` : Pour Box.js, sélectionnez ce drapeau si vous le souhaitez.

#### Paramètres de MalwareJail

- `browser` : Type de navigateur pour la détonation.
- `wscript_only` : Par défaut, la détonation a lieu dans un navigateur en bac à sable. Cette option permet à l'échantillon d'être
  d'être exécuté en WScript uniquement.
- `throw_http_exc` : En sélectionnant l'option throw_http_exc, le bac à sable lèvera une erreur à chaque appel réseau. Ceci
  Ceci est utile pour essayer différents chemins d'exécution de code.
- `download_payload` : Si le service doit permettre à l'échantillon de télécharger n'importe quelle charge utile à partir d'Internet.
- `extract_function_calls` : Les fichiers qui représentent chacun un appel de fonction peuvent être bruyants et peu utiles. Ce drapeau
  permet d'activer cette extraction.
- `extract_eval_calls` : Les fichiers qui représentent chacun un appel d'évaluation peuvent être bruyants et pas particulièrement utiles. Ce drapeau active
  active cette extraction.
- `log_errors` : En mettant ce paramètre à true, on insère un log de l'exception dans les clauses de capture d'exception d'un script. C'est utile pour le débogage.
- `override_eval` : En mettant ce paramètre à true, on utilisera des liens indirects vers les appels `eval`. C'est essentiel lorsque des variables scopées sont utilisées. Voir https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval pour plus d'informations. A utiliser à bon escient.
- `file_always_exists` : Ce paramètre, lorsqu'il est fixé à true, fera en sorte que la méthode `Scripting.FileSystemObject.FileExists` renvoie true.

#### Paramètres de Synchrony

- `enable_synchrony` : Synchrony va très probablement extraire un fichier "nettoyé" à partir de n'importe quel fichier JavaScript, ce qui ajoute de la charge à Assemblyline.
  à Assemblyline. N'activez donc cette option que si vous êtes sûr de vouloir le faire.

### Fonctionnalités incluses avec la connectivité Internet

#### jQuery Fetching

Il existe des échantillons qui intègrent un code malveillant dans les bibliothèques jQuery standard. Si le conteneur Docker de service a
accès à Internet, nous pouvons récupérer la bibliothèque jQuery actuelle et comparer les deux fichiers, en déterminant la différence entre eux et en extrayant le code malveillant.
la différence entre eux, puis extraire la différence (alias le code malveillant). Si le conteneur Docker de service
n'a pas d'accès à Internet, alors mettez la valeur `docker_config` de `allow_internet_access` à `False` dans le fichier
`service_manifest.yml`.

### Liste de sécurité du système Assemblyline

#### Éléments de la liste de sécurité spécifiques à JsJaws

Le fichier `al_config/system_safelist.yaml` contient des suggestions de valeurs de liste de sécurité qui peuvent être ajoutées à la liste de sécurité du système Assemblyline
soit en copiant-collant directement dans l'éditeur de texte de la page `https://<Assemblyline Instance>/admin/tag_safelist`, soit à travers le [Assemblyline Client] (https://github.com/CybercentreCanada/assemblyline_client).

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Jsjaws \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-jsjaws

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
