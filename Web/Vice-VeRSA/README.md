# Vice-VeRSA

Points: 199 (dynamique)

```text
L'administrateur se cache bien d'indiquer aux utilisateurs que leurs messages sont enregistrés. Prouvez-lui qu'on ne peut pas la faire à l'envers aux utilisateurs.

http://challenges2.france-cybersecurity-challenge.fr:5003
```

Tags: `web`, `crypto`

## Analyse

Avec le nom du challenge et les tags, je comprends que le challenge va être orienté crypto avec une partie web. Plus précisément sur du chiffrement RSA.

Dans un premier temps, j'aime bien regarder le code source html de chaque page pour me faire une arboresence de toutes les pages disponibles. Après l'avoir fait sur la première page, je comprends que 4 pages sont disponibles.

```html
<li><a href="/login"><span class="glyphicon glyphicon-log-in"></span> Connexion</a></li>
        <!-- <li><a href="/historique">Historique</a></li> -->
        <!-- <li><a href="/logout"><span class="glyphicon glyphicon-log-out"></span> Logout</a></li> -->
```

| URL | Commentaires |
| -- | -- |
| / | Page permettant de retourner une chaine de caractère. |
| /historique | Page permettant sans doute de récupérer le flag. |
| /login | Page permettant de se connecter avec des identifiants. |
| /logout | Page permettant de se déconnecter. |

Une fois ce listing fait, je vais pouvoir m'attaquer à une analyse plus approfondie.

## Analyse Headers

Lorsque, je visite les différentes pages, uniquement `/` me set un cookie nommé session. Le contenu ressemble fortement à un JSON WEB TOKEN.

```header
Set-Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAifQ.eyJzdHJpbmciOiIiLCJyb2xlIjoiZ3Vlc3QifQ.x1c1Y6wN7W-ri96bzbn90rWP3HHGG-AmtuTzlQrut9LYaK7erEavU2nnD_eA-j-buPuAP7enAqq98hYInVZ7LQz2hh8Pq0aKoOtXrQPEm1XZsTZdKYgnGFT0EgF7MqJvt4w7aoKd_Qw57E6mevT4mpX2N5lhClETsu9Dje78jW7OYKfwPG--Z_47x7BLmLeUnhVBubg67TmRK9hsZLh0FD3PZVE4QjJqMVaU3Cxoe0QTsxSBjikSW5h-8Ldu_SO0hNGppK2HuX0Ca1E_5LPNw5l70T1EGdrk-HoAB3vqrNZIsm-dUYnzCI7qbxMwyJ6bHZS3V63Fm0lChgE1fnPJaw; HttpOnly; Path=/
```

Intéressant, voyons voir ce qu'il contient:

```bash
[ aether@ysera  ~  % ] python3
Python 3.6.9 (default, Jan 26 2021, 15:33:00) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> def decode_jwt(content):
...     content = content.split(".")
...     return [base64.b64decode(i + "====") for i in content] 
... 
>>> decode_jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAifQ.eyJzdHJpbmciOiIiLCJyb2xlIjoiZ3Vlc3QifQ.x1c1Y6wN7W-ri96bzbn90rWP3HHGG-AmtuTzlQrut9LYaK7erEavU2nnD_eA-j-buPuAP7enAqq98hYInVZ7LQz2hh8Pq0aKoOtXrQPEm1XZsTZdKYgnGFT0EgF7MqJvt4w7aoKd_Qw57E6mevT4mpX2N5lhClETsu9Dje78jW7OYKfwPG--Z_47x7BLmLeUnhVBubg67TmRK9hsZLh0FD3PZVE4QjJqMVaU3Cxoe0QTsxSBjikSW5h-8Ldu_SO0hNGppK2HuX0Ca1E_5LPNw5l70T1EGdrk-HoAB3vqrNZIsm-dUYnzCI7qbxMwyJ6bHZS3V63Fm0lChgE1fnPJaw")
[b'{"typ":"JWT","alg":"RS256","kid":"0"}', b'{"string":"","role":"guest"}', [snip]]
```

Il semblerait que pour avoir accès au flag, je doive changer le role dans le token. Il va falloir trouver un moyen de l'exploiter.

## Exploit JWT RSA without Public Key ?

Le décodage du token me donne les informations suivantes:

- `RS256`: Algorithme de chiffrement pour la signature.
- `kid`: Index de la clé publique ?
- `string`: Contient, si rentré la chaîne demandée pour inversion.
- `role`: Notre rôle actuel.

Tout de suite, je décide de vérifier s'il existe un moyen d'exploiter l'`RS256` dans un JWT.

Rapidement, je tombe sur un lien qui explique qu'il est possible de récupérer la clé publique d'un JWT si l'on a deux token avec une signature différente mais de même longueur.

*cf: (<https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/>)*

L'article fournit un code qui est disponible sur github à l'adresse suivante :(<https://github.com/silentsignal/rsa_sign2n/tree/release/CVE-2017-11424>).

Après avoir lu l'article et compris le fonctionnement de l'attaque, je crée deux tokens différents avec une signature de même longuer. Ces tokens seront en argument au script qui me retournera la clé publique (si trouvé).

Pour cela rien de plus simple, il suffit de se rendre sur la page `/` et de submit une chaîne à inverser.

## Les problèmes

Après avoir créé deux tokens différents, je me rends compte que le `kid` dans le header du JWT n'est pas le même. Il y aurait donc plusieurs clés publiques ?

Quelques tests de récupération des tokens plus tard, je comprends qu'il existe trois clés publiques.

Je vais donc devoir récupérer non pas deux mais 6 tokens. 2 pour chaque clé publique un avec la string `guest` et un autre avec la string `admin`. Les valeurs des strings importent peu, il faut seulement qu'elles soient de même longueur.

## Récupération des tokens

Pour ne pas avoir à faire cette action à la main (qui peut être longue), je décide de faire un petit script python:

```python
#!/usr/bin/python3

import requests
import base64

URL = "http://challenges2.france-cybersecurity-challenge.fr:5003/"

def get_token(value):
    return requests.post(URL, data={"string_1": value}).cookies["session"]

def decode_token(token):

    header, content, signature = token.split(".")

    header = base64.b64decode(header + "====")
    content = base64.b64decode(content + "====")
    #signature = base64.b64decode(signature + "====")

    return header, content, signature

kid_zero = list()
kid_one = list()
kid_two = list()

string = ["guest", "admin"]

for index, value in enumerate(string):

    while True:

        token = get_token(value)

        header, content, signature = decode_token(token)

        if b'"kid":"0"' in header:
            if len(kid_zero) == index + 1: continue
            kid_zero.append(token)
        elif b'"kid":"1"' in header:
            if len(kid_one) == index + 1: continue
            kid_one.append(token)
        elif b'"kid":"2"' in header:
            if len(kid_two) == index + 1: continue
            kid_two.append(token)

        if len(kid_zero) == index + 1 and len(kid_one) == index + 1 and len(kid_two) == index + 1:
            break

print(kid_zero, kid_one, kid_two)
```

Ce script me renvoie dans le stdout, trois listes contenant chacune deux éléments. Un JWT avec la string `guest` à l'intérieur et l'autre `admin` (les valeurs importent peu tant quelles sont de mêmes longeur).

## RSA Public Key

Je peux maitenant sauvegarder ces JWT dans des fichiers pour les passer ensuite au script trouvé plus haut.
*Je vous conseille de créer un venv (python) pour ce script qui utilise des versions particulières*

Le script va me permettre de calculer le module public en se basant sur deux paires de message-signature.

```bash
(CVE-2017-11424) [ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA/rsa_sign2n/CVE-2017-11424  % ] python3 x_CVE-2017-11424.py $(cat jwt_kidzero_guest) $(cat jwt_kidzero_admin)
[*] GCD:  0x1
[snip]
[+] Found n with multiplier 5  :
 0xd1885b6463c836e075d71f5d29d2aec47a8e5794e9c6ed7f0ca5754bd17f8bbb669f0fbdda70c66b85a2fcc52741d4c279b73c25c5452c3322521b8a3c6d15bc0a97ca687e7ee2cae0fb9e9b2d047132a15cbaa3139a9a40d65c0871d5cd9e2aea4a45b6dc37e127e0bc1de28cdc19e3a612002ec71bcac4009451aadbd2dfc300674fe56eb258e454076e82e330cfd772dc28feb9fdcd17462dff9e4edfc60eef0fe33ab889daa8d35ec2a9cc6dcaa9b6f3f35c1830cdb964575ce83ea9dfcd105cd472407c3f224a8cbc3d928932ef33128c17417c8c9d19286de171eb8391c187eee7c0a2c902c0cfbdf0fc5aa9f5b5f4205a20fd783f3453ae1b541f95a3
[snip]
(CVE-2017-11424) [ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA/rsa_sign2n/CVE-2017-11424  % ] python3 x_CVE-2017-11424.py $(cat jwt_kidone_guest) $(cat jwt_kidone_admin)
[*] GCD:  0x2
[snip]
[+] Found n with multiplier 2  :
 0xbb77d42d493ec8e390b6fc986091945cdf998876c95c950efb5192bc38b0edc33d2eceaff96fb21d11b25b24e329924b21ef4b8170d0da00b90cdb396481d43a6efb56e8bbc60238bcf86d151c73dcc15a21a988f45338abdb9ca12ba15cc12565ae0a56dfca0446a932f2ecd934e5d6b8bc0b32f8c80db35a8d004954d47dab127d52b2cd0459bc13f96859a022641fdc2542cf0572b6d81bd3d5a3ba0c5cf708ccda75376aae44833e6f6c8c73b120639c6ab2dd9861dc25270b45f1a23ed093fa7bda13b3188c60b18a7a6e56340f1d76176cf255ae3351bea178d1b54a6613481a9e6a28edd0a3fdb24d72c4cc398d3b715978e35b77b3ec829527a7f299
[snip]
(CVE-2017-11424) [ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA/rsa_sign2n/CVE-2017-11424  % ] python3 x_CVE-2017-11424.py $(cat jwt_kidtwo_guest) $(cat jwt_kidtwo_admin)
[*] GCD:  0x3
[snip]
[+] Found n with multiplier 3  :
 0xb4112d8fdb1df6e1c375d2dc1b971b57d7d72426c10e7d3b52681be7babaceb26f8e3629d37f8f14ec998d51b80f4022b668bef0588fdba57b0a97735825012327bc011ab05451b2c2e518cd6608ac745dcb5a24aa9cf8e7abae777cd7092f1b164440b027ad966a567b305367bf57ad472c0b763f4471cc948b40c1e4e3fcd8a114cecf96e1201609b3f9270702de2f1906f51d10307ea38d98843442994a6a87d03dec26416ce4ea3677ecf34f104479d1553244380b523eec2fcb85383eac17cada171b236332b26add3cdc04d0183d8172b6c787a8d80490de662c6b2909c5ebaaef3da5982fcd797e4a7e8f000d9f12f3efd256d05cd1ab259c0d9f38fd
[snip]
```

Parfait ! Le script me renvoie la clé publique associé à chacun des trois `kid`.

Il est maintenant l'heure de récupérer les clés privées !

## RSA Cracking

### factordb

Dans un premier temps, je vais chercher la facilité en cherchant si une de ces clés n'est possiblement pas sur factordb.

Pour me faciliter le travail, j'avais créé un script auparavant qui va directement requêter factordb et me renvoie l'état du nombre.

```bash
[ aether@ysera  ~  % ] search_prime 26451045880964917513500384554170817361416002571109323756587984316856882166600328406421489096897898642651442847900199601304963538350047883183579130756781323269629194136721900337192506462030774874728607767647872177503355240337120882142783093099150509303327996012421752957488757794618331761757840545947319249000775787430347930747865590144543178555226128667553193702710789911878998342585553168381830185135508390340657676458670407304327894647689701103713000730792845731920670463877317625170112005192759353936549709813113349510590820755042322951273495963408223355841314599444712000223270748965159897835541243233949292926371
[+] C: 2645104588...71&lt;617&gt; = 2645104588...71&lt;617&gt;
[ aether@ysera  ~  % ] search_prime 23665652820134805374198160670285833921391080168347242686789486999501147452564182203815403432586037211580956807418390515260607797114130600470792877974783209468301203025857100674184179834125773001492324249995631518632190591284347199695615566699061802073984938509524118604141487334019736930099338674532167272834445210127085946363143475338489425347697379610470637836163978122048233036129066473971261891100314946785632986774865922264847742332593870916133974536065637794870077767216697298265895973548680864568583117925623450171604556505682160596979527747518700282565884296112666999750704513275226624446992913735981325611673
[+] C: 2366565282...73&lt;617&gt; = 2366565282...73&lt;617&gt;
[ aether@ysera  ~  % ] search_prime 22731365669722716790523988469211174698469647719778831863970396221572599409300719240441972167971859096690301602182969197363505496123904858731217310323069800081347653770883702578911025506738080849436708669671186348533493041292769716064576663922411644860482974431829677048235872088045298198687332564790708320625966491365742866664943328632514191628724244741007713325357654856556937713627169871880861184843650059723398603225879352578010649653414401635886489704537350073827506117761008999068169633867812485790098429368696301604341046865861665894241805556589392944953338821552542037920683039404461145689037243695687228406013
[+] C: 2273136566...13&lt;617&gt; = 2273136566...13&lt;617&gt;
```

Aïe, aucun module n'est connu.

*C indique Composite c'est à dire qu'aucun facteur n'est connu (cf: <http://factordb.com/status.html>)*

### RsaCtfTool

Toujours dans la facilité, je décide de passer les modules dans le célèbre outil RsaCtfTool, qui ne me renvoie rien non plus :/.

### Google is my friend

Après quelques ~~de multiples~~ recherchent, je trouve un court diaporama explicant 15 techniques pour casser la sécurité du RSA.

*cf: <https://speakerdeck.com/rlifchitz/15-ways-to-break-rsa-security?slide=14>*

La slide 14 m'intéresse beaucoup. Elle indique qu'il est possible de retrouver un nombre premier du module si plusieurs clés publiques partagent le même. Cela grâce au PGCD (Plus Grand Commun Diviseur).

Je test directement cette technique avec un court script python:

```python
from Crypto.PublicKey import RSA

import sys
import math
from cryptomath import cryptomath

n = [22731365669722716790523988469211174698469647719778831863970396221572599409300719240441972167971859096690301602182969197363505496123904858731217310323069800081347653770883702578911025506738080849436708669671186348533493041292769716064576663922411644860482974431829677048235872088045298198687332564790708320625966491365742866664943328632514191628724244741007713325357654856556937713627169871880861184843650059723398603225879352578010649653414401635886489704537350073827506117761008999068169633867812485790098429368696301604341046865861665894241805556589392944953338821552542037920683039404461145689037243695687228406013,
23665652820134805374198160670285833921391080168347242686789486999501147452564182203815403432586037211580956807418390515260607797114130600470792877974783209468301203025857100674184179834125773001492324249995631518632190591284347199695615566699061802073984938509524118604141487334019736930099338674532167272834445210127085946363143475338489425347697379610470637836163978122048233036129066473971261891100314946785632986774865922264847742332593870916133974536065637794870077767216697298265895973548680864568583117925623450171604556505682160596979527747518700282565884296112666999750704513275226624446992913735981325611673,
26451045880964917513500384554170817361416002571109323756587984316856882166600328406421489096897898642651442847900199601304963538350047883183579130756781323269629194136721900337192506462030774874728607767647872177503355240337120882142783093099150509303327996012421752957488757794618331761757840545947319249000775787430347930747865590144543178555226128667553193702710789911878998342585553168381830185135508390340657676458670407304327894647689701103713000730792845731920670463877317625170112005192759353936549709813113349510590820755042322951273495963408223355841314599444712000223270748965159897835541243233949292926371
]

e = 65537

p = math.gcd(n[0], n[1])

for i in range(0, 3):

    q = n[i] // p

    d = cryptomath.findModInverse(e, (q - 1) * (p - 1))

    keyrsa = ((n[i], e, d, p, q))

    key = RSA.construct(keyrsa)

    private = key.exportKey("PEM")

    with open(f"privatekey{i}.pem", "wb") as f:
        f.write(private)
```

Ca fonction ! Les trois modules publics partagent donc un même nombre premier.

## Signature

Je dois maintenant forger un token avec pour `"role": "admin"` et le submit au site pour récuperer le flag. A nouveau, je crée un petit script bash cette fois-ci, pour générer mon token.

```bash
header=$(echo -n '{"typ":"JWT","alg":"RS256","kid":"0"}' | base64 | sed s/\+/-/ | sed -E s/=+$//)
content=$(echo -n '{"string":"","role":"admin"}' | base64 | sed s/\+/-/ | sed -E s/=+$//)
signature=$(echo -n "$header.$content" | openssl dgst -sha256 -binary -sign privatekey0.pem | openssl enc -base64 | tr -d '\n=') 

echo $header.$content.$signature
```

Il ne me reste plus qu'à tester !

```bash
[ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA  % ] bash forge_jwt.sh 
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAifQ.eyJzdHJpbmciOiIiLCJyb2xlIjoiYWRtaW4ifQ.MThb5+k9qipf8+sXD9oOhznYwcMDZbC/h5voYQj1hILtN4pvwv5FWT5To1eJaM4MDVIgNFtChZUShDVT23IR9OXkViZqYgNEm8RUVkwDeJGZkgNJketmUVGeh89+/tY74kr/z0SLgYKi3f/DhtiJTRu1THKVykPtuKaaBxXKwDl80MYQZ6ndk/xvhR/4/ojyjG5njYQk7gMOH2k0d4mXpG/dx+/g4HarS3f96UVsBWOXAnBdXaX21rPhGOLKFZsKTkawMh9t4+63f8XB1l++acQzuXv+r+nxXvuFaWTOhLEYDT1a9+LZrf9EmO01tXPJianA7hFImIGC8f+EkQQsxg

[ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA  % ] curl "http://challenges2.france-cybersecurity-challenge.fr:5003/historique" --cookie "session=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAifQ.eyJzdHJpbmciOiIiLCJyb2xlIjoiYWRtaW4ifQ.MThb5+k9qipf8+sXD9oOhznYwcMDZbC/h5voYQj1hILtN4pvwv5FWT5To1eJaM4MDVIgNFtChZUShDVT23IR9OXkViZqYgNEm8RUVkwDeJGZkgNJketmUVGeh89+/tY74kr/z0SLgYKi3f/DhtiJTRu1THKVykPtuKaaBxXKwDl80MYQZ6ndk/xvhR/4/ojyjG5njYQk7gMOH2k0d4mXpG/dx+/g4HarS3f96UVsBWOXAnBdXaX21rPhGOLKFZsKTkawMh9t4+63f8XB1l++acQzuXv+r+nxXvuFaWTOhLEYDT1a9+LZrf9EmO01tXPJianA7hFImIGC8f+EkQQsxg"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

La clé privée avec le kid 0 ne semble pas fonctionner. J'essaye alors le kid 1 avec sa clé privée associé.

Je change le kid et le nom de la clé privée mon script bash:

```bash
header=$(echo -n '{"typ":"JWT","alg":"RS256","kid":"1"}' | base64 | sed s/\+/-/ | sed -E s/=+$//)
content=$(echo -n '{"string":"","role":"admin"}' | base64 | sed s/\+/-/ | sed -E s/=+$//)
signature=$(echo -n "$header.$content" | openssl dgst -sha256 -binary -sign privatekey1.pem | openssl enc -base64 | tr -d '\n=') 

echo $header.$content.$signature
```

```bash
[ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA  % ] bash forge_jwt.sh 
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdHJpbmciOiIiLCJyb2xlIjoiYWRtaW4ifQ.VUKmrNiD29PObkEE7fLN8Gw3EiLGorrRdzVheaekqQmU4CHFcGuvvw5t4DzCI6KtcpNj235eUxUcNc3sua4TVOj6zd1tQKFtC6YTunwP95Q8pmrc+hIFKZTZRMuuHtHXVKVSA7QaIUlQWokryeqsRdvQ8l9ZhYKA9ybJDPwVao+sOHIegXFjo2oZeS2QtpJR1S9tDZVTFXfsolRbzlN1xE+sZV4T4A+5xtNQHOBRVEDqRR2/vjorgbCxGI21OJnEUyvreMEBjn6kBxwhn3w3N/CmTaM/0ECepYaOjHKh2DiBWXrMsn3u1TdPMnOZMSvsglFuzBRD71GOIl5hOcisww
[ aether@ysera  ~/Documents/FCSC/2021/web/Vice-veRSA  % ] curl "http://challenges2.france-cybersecurity-challenge.fr:5003/historique" --cookie "session=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdHJpbmciOiIiLCJyb2xlIjoiYWRtaW4ifQ.VUKmrNiD29PObkEE7fLN8Gw3EiLGorrRdzVheaekqQmU4CHFcGuvvw5t4DzCI6KtcpNj235eUxUcNc3sua4TVOj6zd1tQKFtC6YTunwP95Q8pmrc+hIFKZTZRMuuHtHXVKVSA7QaIUlQWokryeqsRdvQ8l9ZhYKA9ybJDPwVao+sOHIegXFjo2oZeS2QtpJR1S9tDZVTFXfsolRbzlN1xE+sZV4T4A+5xtNQHOBRVEDqRR2/vjorgbCxGI21OJnEUyvreMEBjn6kBxwhn3w3N/CmTaM/0ECepYaOjHKh2DiBWXrMsn3u1TdPMnOZMSvsglFuzBRD71GOIl5hOcisww"
<!DOCTYPE html>
<html lang="en">
[snip]
        
        <li>FCSC{e1f444434b8c52a812e6dd0f59b71c32253018473384476feacc2fc9eefdc7be}</li>
[snip]
```

Yes ! La clé privée du kid 1 passe et je peux récupérer mon flag !

flag: `FCSC{e1f444434b8c52a812e6dd0f59b71c32253018473384476feacc2fc9eefdc7be}`
