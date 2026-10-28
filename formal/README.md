# Protocole de révocation : modèle formel TLA+

`AtomicRevocation.tla` est un modèle abstrait, **pas** une preuve du code Python ni de PostgreSQL. Il représente une révocation, la transaction locale et son outbox, l'ancrage, la confirmation, une restauration ancienne et la réconciliation. La vivacité conditionnelle et les modèles multi-certificats restent à élaborer.

Avec `tla2tools.jar` installé localement :

```bash
java -cp /chemin/vers/tla2tools.jar tlc2.TLC -config formal/AtomicRevocation.cfg formal/AtomicRevocation.tla
```

L'exploration et les mutants Python sont **bornés** : `python -m scripts.formal_mutation_runner`. Ce programme n'exécute pas TLC. Les rapports CI doivent distinguer les deux familles de vérification.
