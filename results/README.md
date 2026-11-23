# Results

Written by `results/run_all.py`, which ran every check below and saved TLC's outputs in `results/outputs/`.

## Main runs

| Run | TLC's verdict | Distinct states | States generated | Search depth | Trace length | Output |
|---|---|---|---|---|---|---|
| The spec, three tool calls, all checks, deadlock check on | holds | 321,510 | 1,903,762 | 27 | - | `outputs/1_Gate.txt` |
| The spec, four tool calls, all checks | holds | 25,995,938 | 195,250,814 | 35 | - | `outputs/2_Gate_4calls.txt` |
| The two-call model, check 8 | holds | 5,202 | 22,938 | 19 | - | `outputs/3_GateLive.txt` |
| The version that waits forever, check 8, with -deadlock | broken | 2,346 | 8,606 | - | 12 | `outputs/4_WrongWaitsForever_liveness.txt` |
| Reachability: no call ever starts (must break) | broken | - | - | 8 | 8 | `outputs/5_GateReach.txt` |

## Each broken version against each check alone

One TLC run per cell, with `TypeOK` and that one check, deadlock reporting off. Check numbers are those of the top-level README. "broken (n states)" gives the length of TLC's trace; "holds" means TLC searched every reachable state and the check held.

| Broken version | 1 (state form) | 1 (step form) | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| WrongRunBeforeJournal | broken (3 states) | broken (4 states) | holds | holds | broken (3 states) | holds | holds | holds |
| WrongRunAfterGivingUp | broken (5 states) | broken (5 states) | holds | holds | broken (5 states) | holds | holds | holds |
| WrongWitnessInMemory | broken (8 states) | broken (9 states) | broken (6 states) | holds | holds | holds | holds | holds |
| WrongFingerprintBeforeJournal | holds | holds | holds | broken (4 states) | holds | holds | broken (3 states) | holds |
| WrongRunWithoutHeldStamp | holds | holds | holds | holds | broken (6 states) | holds | holds | holds |
| WrongRunAfterRefusal | holds | holds | holds | holds | holds | broken (8 states) | holds | holds |
| WrongStampAndRunInOneStep | holds | broken (5 states) | holds | holds | broken (6 states) | holds | holds | holds |
| WrongWaitsForever | holds | holds | holds | holds | holds | holds | holds | broken (4 states) |

## Fingerprints of the files checked (sha256)

```
530fd02d236b525478990eb0f22b2652484931752372ebc1592042d21acd9ebd  model/Gate.cfg
207effec1450dce9d4a86b00af4693c096e26ae258229cb12265c28c235804c3  model/Gate.tla
02afe0cabc68c935a3a602b2b25c96194d2773d687f1b2379116c1292e099d70  model/GateLive.cfg
110dce7ae92ccf10a68c8f606297f976ed692e0388cc87ff04e91d2aed22380c  model/GateLive.tla
8da1e1623cefac9b6cedc5300777a1e8f8e43893954a12ef5870b805f88f3345  model/wrong/WrongFingerprintBeforeJournal.cfg
1e19a16b5b92e33807b99e658f9ee885dbf1abc5316f6c960088cdcf31a162d1  model/wrong/WrongFingerprintBeforeJournal.tla
b32ae548afb37bc486d72a97be15dcee5912e3c60924d725af2472d48138be6a  model/wrong/WrongRunAfterGivingUp.cfg
3264f7b5051c6657252771a47dc51d1dc17f1d5b8884bcba189c348092906c54  model/wrong/WrongRunAfterGivingUp.tla
78680e688e4f209d37ad3cd39548c58659dabbab3b67bef73d4da088875299b0  model/wrong/WrongRunAfterRefusal.cfg
8f7d49ab1d1c9b139dc0d0503dff1bdc4da4ce5d68142a314f1b669f66b71562  model/wrong/WrongRunAfterRefusal.tla
a6317cf5dd323a2c78a91560b16f5d196083bcea736f014667bc957bd0f28d71  model/wrong/WrongRunBeforeJournal.cfg
ed70402fb5cea56279c6d2d615a0a180583f6617cb8c08e0848297df9839fe06  model/wrong/WrongRunBeforeJournal.tla
91e63e273ed9fcb347122c8cea7623c8308c4145c67a429ad60820bd62f84853  model/wrong/WrongRunWithoutHeldStamp.cfg
65249a24564d0d54de458704c43d87fab95488dbbf318b048df0d945dfb03a14  model/wrong/WrongRunWithoutHeldStamp.tla
3987c02d89def76de0aee553522832a5a4e05cc2d6fd3ffbcdef6541f3308a97  model/wrong/WrongStampAndRunInOneStep.cfg
19445c1cae3577940e6e0d5e42f9274d9f8ffc14541ae695aa5e35bda5085d5a  model/wrong/WrongStampAndRunInOneStep.tla
85d62b71a35b7e42d98b9da336520ead05c299b709719610623964f710d56c16  model/wrong/WrongWaitsForever.cfg
b933eba88dee17a387a639261151767f3a1f905dbd6902e08666bd230b5ed2c2  model/wrong/WrongWaitsForever.tla
ae00c32e174de745d875ee5b27a08b02b9d24d9cb1914122ff506b4ac42ff4fb  model/wrong/WrongWitnessInMemory.cfg
6df5b6267753ce535b85e390438a8d70ca949fb78d45aeb0eb0392cca459bce4  model/wrong/WrongWitnessInMemory.tla
5bbba49993ddbe630e48e1470c80aa6e7d598291a68e0484bed7c33751e49a69  results/GateReach.tla
27f7a7fc0cc6a014f8388c44ce57ac990caf33080743b4c89111eacc0500224a  results/GateReach.cfg
9c00e7c6017aacfb626d4f6ce8faa25539a3e5f6c09959ee2d4eecf4d448c104  results/Gate_4actions.cfg
6241ea49b7b4fc17d7d9ed92ed93fa222f20083c63dd62235268fe7cd3655451  results/run_all.py
```
