# Smemstat: shared memory statistics

Smemstat reports the physical memory usage taking into consideration shared memory. The tool can either report a current snapshot of memory usage or periodically dump out any changes in memory.

## Smemstat command line options

* -c get command name from processes comm field
* -d strip directory basename off command information
* -g report memory in gigabytes
* -h show this help information
* -k report memory in kilobytes
* -l show long (full) command information
* -m report memory in megabytes
* -o file dump data to json formatted file
* -p proclist specify comma separated list of processes to monitor
* -q run quietly, useful for -o output only
* -s show short command information
* -t top mode, show only changes in memory
* -T top mode, show top memory hoggers 

## Example Output

Analyise 60 seconds of activity with 10 seconds duration per sample, 6 samples

```
smemstat 10 6
Change in memory:
  PID       Swap       USS       PSS       RSS User       Command
  7513     0.0 B   786.4 K   786.4 K   786.4 K king       /usr/lib/firefox/firefox
  6152     0.0 B    34.4 K    35.6 K    36.8 K king       /usr/lib/thunderbird/thunderbird
  2459     0.0 B    24.4 K    24.4 K    24.4 K king       /usr/lib/x86_64-linux-gnu/hud/hud-service
  2670 -5734.4 B    16.0 K    16.0 K    16.0 K king       compiz
  2289 -6553.6 B  8192.0 B  8192.0 B  8192.0 B king       init
  2763 -5324.8 B  5324.8 B  5324.8 B  5324.8 B king       nautilus
 13120     0.0 B  4915.2 B  4915.2 B  5324.8 B king       ./smemstat
  2372     0.0 B  3276.8 B  3276.8 B  3276.8 B king       /usr/bin/ibus-daemon
  2409     0.0 B   409.6 B   409.6 B   409.6 B king       /usr/lib/ibus/ibus-ui-gtk3
  2384  -409.6 B   409.6 B   409.6 B   409.6 B king       /usr/lib/x86_64-linux-gnu/bamf/bamfdaemon
Total:   -17.6 K   883.2 K   884.4 K   886.0 K

  PID       Swap       USS       PSS       RSS User       Command
  7513     0.0 B  1646.0 K  1646.1 K  1646.4 K king       /usr/lib/firefox/firefox
  2459     0.0 B   235.6 K   235.6 K   235.6 K king       /usr/lib/x86_64-linux-gnu/hud/hud-service
  2289   -12.0 K    16.8 K    16.8 K    16.8 K king       init
  2409     0.0 B   819.2 B   819.2 B   819.2 B king       /usr/lib/ibus/ibus-ui-gtk3
  2384  -409.6 B   409.6 B   409.6 B   409.6 B king       /usr/lib/x86_64-linux-gnu/bamf/bamfdaemon
 13120     0.0 B     0.0 B     0.0 B  2048.0 B king       ./smemstat
  6152     0.0 B  -250.4 K  -250.4 K  -250.4 K king       /usr/lib/thunderbird/thunderbird
Total:   -12.4 K  1649.2 K  1649.3 K  1651.6 K

  PID       Swap       USS       PSS       RSS User       Command
  6152 -7372.8 B   198.8 K   198.8 K   198.8 K king       /usr/lib/thunderbird/thunderbird
  2289     0.0 B   409.6 B   409.6 B   409.6 B king       init
  7146     0.0 B     0.0 B   204.8 B   409.6 B king       mumble
  2596     0.0 B     0.0 B   204.8 B   409.6 B king       /usr/bin/pulseaudio
  2670     0.0 B   -19.2 K   -19.2 K   -19.2 K king       compiz
  7513     0.0 B -2927.6 K -2927.6 K -2927.6 K king       /usr/lib/firefox/firefox
Total: -7372.8 B -2747.6 K -2747.2 K -2746.8 K

  PID       Swap       USS       PSS       RSS User       Command
  7070     0.0 B    14.8 K    14.8 K    14.8 K king       gnome-terminal
  6988     0.0 B     0.0 B   204.8 B     0.0 B king       xchat-gnome
  6152     0.0 B  -243.2 K  -255.3 K  -279.6 K king       /usr/lib/thunderbird/thunderbird
  7513     0.0 B  -378.4 K  -376.5 K  -382.0 K king       /usr/lib/firefox/firefox
Total:     0.0 B  -606.8 K  -616.8 K  -646.8 K

  PID       Swap       USS       PSS       RSS User       Command
  6152  -819.2 B   619.6 K   619.6 K   619.6 K king       /usr/lib/thunderbird/thunderbird
  7513 -1228.8 B   542.0 K   542.0 K   542.0 K king       /usr/lib/firefox/firefox
  2474     0.0 B    66.4 K    66.4 K    66.4 K king       /usr/lib/unity/unity-panel-service
  2459     0.0 B    28.8 K    28.8 K    28.8 K king       /usr/lib/x86_64-linux-gnu/hud/hud-service
  7070     0.0 B    12.4 K    12.4 K    12.4 K king       gnome-terminal
  2289 -5734.4 B  7372.8 B  7372.8 B  7372.8 B king       init
  2670     0.0 B  6553.6 B  6553.6 B  6553.6 B king       compiz
  2409 -1638.4 B  2048.0 B  2048.0 B  2048.0 B king       /usr/lib/ibus/ibus-ui-gtk3
Total: -9420.8 B  1284.8 K  1284.8 K  1284.8 K

  PID       Swap       USS       PSS       RSS User       Command
  6152  -409.6 B  1557.6 K  1557.6 K  1557.6 K king       /usr/lib/thunderbird/thunderbird
  2459     0.0 B   106.0 K   106.0 K   106.0 K king       /usr/lib/x86_64-linux-gnu/hud/hud-service
  2289 -7782.4 B    10.4 K    10.4 K    10.4 K king       init
  2670     0.0 B  3276.8 B  3276.8 B  3276.8 B king       compiz
  2384 -1228.8 B  1228.8 B  1228.8 B  1228.8 B king       /usr/lib/x86_64-linux-gnu/bamf/bamfdaemon
  7513     0.0 B  -190.0 K  -190.0 K  -190.0 K king       /usr/lib/firefox/firefox
Total: -9420.8 B  1488.4 K  1488.4 K  1488.4 K
```

Current snapshot of memory usage, report in megabytes, strip off leading directory path off command and also output results into a json formatted file:

```
sudo ./smemstat -dm -o smemstats.json
  PID       Swap       USS       PSS       RSS User       Command
  7513     33240    218624    220649    226780 king       firefox
  6152     52936    161804    163568    169300 king       thunderbird
  1245       260     76196     79209     83228 root       X
  2459      6692     48924     49410     51916 king       hud-service
  2474     10140     42716     43563     47496 king       unity-panel-service
  2670     77108     33596     35170     40984 king       compiz
  7070      3492     13608     14640     19516 king       gnome-terminal
  7146     17272     10612     12486     16828 king       mumble
  2289     18776     11008     11070     12092 king       init
  3118     41636      9724      9790     11104 king       python
  6988      8716      7388      8402     13016 king       xchat-gnome
  2763     18240      6180      7425     11664 king       nautilus
 10262         0      4240      4535      5736 king       bash
  2596      1460      3728      4129      5516 king       pulseaudio
  1256         0      3664      3717      5324 root       accounts-daemon
  2409      2532      3500      3623      5648 king       ibus-ui-gtk3
  2372      2556      3404      3441      4712 king       ibus-daemon
  2455      6440      3236      3398      5732 king       unity-settings-daemon
  2287      1688      3128      3193      4512 king       gnome-keyring-daemon
  1199        44      3120      3145      4436 root       lightdm
  1153      1400      3060      3085      3884 root       libvirtd
  2748      5276      2552      2950      5660 king       nm-applet
  1141       300      2640      2786      4308 whoopsie   whoopsie
  1613         0      2728      2781      4376 root       upowerd
  2384     11212      2448      2533      4504 king       bamfdaemon
   897         0      2428      2474      3924 root       polkitd
  2810         0      2340      2411      3988 root       udisksd
  6786         0      2304      2314      2984 root       dhclient
  6790         0      2300      2310      2980 root       dhclient
   869      2168      2024      2155      4004 root       NetworkManager
  2535      3960      2012      2095      3744 king       indicator-sound-service
 13277         0      1588      1718      2836 root       sudo
  2349       840      1604      1708      2408 king       dbus-daemon
     1       244      1596      1654      2632 root       init
  2542       300      1556      1606      3216 king       indicator-session-service
   470       208      1412      1517      2280 messagebus dbus-daemon
  2516      3840      1436      1491      3372 king       indicator-keyboard-service
  1250        12      1308      1352      2084 root       wpa_supplicant
  2802       796      1300      1345      2748 king       gvfs-udisks2-volume-monitor
  2892         0      1324      1336      2116 root       cupsd
  2469      2848      1268      1318      3112 king       gnome-session
  1583        28      1244      1272      2472 root       lightdm
  3067      7356      1108      1177      2612 king       zeitgeist-datahub
  2530      2676      1088      1135      2704 king       indicator-datetime-service
   822        72      1124      1131      1828 root       ModemManager
  3730     73668       892      1028      2584 king       unity-control-center
   615         4      1016      1023      1572 syslog     rsyslogd
  1171         0       944       970      1920 root       cups-browsed
  3016       856       824       955      2456 king       mission-control-5
  8219      2488       688       951      2036 king       bash
  2740      2084       900       931      2584 king       unity-fallback-mount-helper
  5495     11968       880       917      2276 king       unity-scope-loader
  3501       384       852       906      2444 king       gvfsd-http
  5486      4744       864       905      2248 king       unity-scope-home
  3072      2584       700       893      2328 king       zeitgeist-daemon
  5497      1608       800       875      2396 king       unity-files-daemon
   546         0       668       722      1832 root       thermald
  3275      2568       664       721      2164 king       update-notifier
   649       912       692       703      1520 colord     colord
  2739      2256       648       673      2204 king       polkit-gnome-authentication-agent-1
  2363       376       320       646      1820 king       window-stack-bridge
  2647      4296       592       638      1932 king       notify-osd
  2524       272       576       621      2200 king       indicator-power-service
  2522       368       592       618      1984 king       indicator-messages-service
  2457       392       592       614      1836 king       ibus-engine-simple
   474       360       604       610      1232 root       systemd-udevd
  1009       512       592       605       956 root       upstart-file-bridge
   573        28       580       600      1540 root       systemd-logind
  2388       184       476       518      1960 king       gvfsd
   460        56       476       498      1028 root       upstart-udev-bridge
  3332      2568       464       491      1788 king       deja-dup-monitor
  2565       780       432       468      1876 king       indicator-application-service
  2854       628       428       446      1500 king       gvfsd-trash
  1873         0       436       441      1032 root       unity-greeter-session-broadcast-service
  2422       304       320       422      1336 king       dbus-daemon
  2404       420       400       419      1636 king       ibus-dconf
  1131       356       392       417      1176 root       sshd
  3010      4892       400       415      1576 king       telepathy-indicator
  2539      5336       392       410      1612 king       indicator-printers-service
   638       156       368       387      1184 avahi      avahi-daemon: running [lenovo.local]
  2399      2472       364       386      1636 king       gvfsd-fuse
  2826      1460       324       358      1424 king       gconfd-2
  1208         8       344       346       784 kernoops   kerneloops
  2075         0       300       343      1156 nobody     dnsmasq
  1016       264       324       331       684 root       upstart-socket-bridge
  2639     36028       308       329      1416 king       evolution-calendar-factory
  3078       832       300       313      1400 king       zeitgeist-fts
  2061         0       252       292       804 libvirt-dn dnsmasq
  1146         4       284       288       684 root       irqbalance
  1352        68       264       278       784 root       acpid
  1686         0       252       259       940 rtkit      rtkit-daemon
 13278         0       228       246       912 root       smemstat
  2431       436       232       246      1268 king       at-spi2-registryd
  2400       128       224       243       788 king       upstart-file-bridge
  2394       192       184       205       640 king       upstart-dbus-bridge
  1138        96       184       199       812 root       cron
  2407        92       152       173       604 king       upstart-dbus-bridge
  1084         0       164       171       836 root       getty
  1505         0       160       167       832 root       getty
  1074         0       160       167       832 root       getty
  2359        92       148       166       968 king       upstart-event-bridge
  1087         0       152       159       824 root       getty
  1083         0       152       159       824 root       getty
  7020      1232       100       135      1052 king       sd_espeak
  7016       480       100       133       976 king       sd_cicero
  7013       488        96       129       964 king       sd_dummy
  7010       496        96       129       964 king       sd_generic
  7079        64       112       119       688 king       gnome-pty-helper
  2566      1148       112       119       900 king       indicator-sync-service
   572       200        84        89       624 root       bluetoothd
  2417      1684        64        72       836 king       ibus-x11
  2831      2728        64        70       752 king       gvfs-afc-volume-monitor
  1139       132        48        49       208 root       atd
  1069         0        40        41        48 gitlog     svlogd
  2603      1208        24        29       636 king       dconf-service
  1065         0        28        29        36 root       runsvdir
  1067         0        24        25        32 root       runsv
  1070       148         8        15       572 gitdaemon  git-daemon
  2361      2776         8        13       620 king       url-dispatcher
  2844      2836         4        11       732 king       gvfs-gphoto2-volume-monitor
  2840      2652         4        11       728 king       gvfs-mtp-volume-monitor
  2568      4988         4        11       724 king       evolution-source-registry
  1066       160         4        11       676 root       getty
  3189       532         4        10       672 king       unity-webapps-service
  2877      2608         4        10       676 king       gvfsd-metadata
  2864       640         4        10       692 king       gvfsd-burn
  2523       636         4        10       708 king       indicator-bluetooth-service
  2405       628         4        10       700 king       at-spi-bus-launcher
  7025       244         4         9       452 king       speech-dispatcher
  3089        92         4         8       440 king       cat
   641       248         4         5       156 avahi      avahi-daemon: chroot helper
  2342       308         4         4        80 king       ssh-agent
Total:    546700    742172    762814    929280
```

Note: Memory reported in units of megabytes.
